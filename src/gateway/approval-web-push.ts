// Delivers generic approval notifications to Web Push subscriptions whose
// persisted browser binding still has current approval and visibility access.
import {
  GATEWAY_CLIENT_IDS,
  GATEWAY_CLIENT_MODES,
} from "../../packages/gateway-protocol/src/client-info.js";
import { resolveGatewayPublicOrigin } from "../config/gateway-public-origin.js";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import {
  hasEffectivePairedDeviceRole,
  listDevicePairing,
  type PairedDevice,
} from "../infra/device-pairing.js";
import {
  listBoundWebPushSubscriptions,
  prepareWebPushNotificationSender,
  type BoundWebPushSubscription,
} from "../infra/push-web.js";
import { roleScopesAllow } from "../shared/operator-scope-compat.js";
import { resolveUserProfileId } from "../state/user-profiles.js";
import { normalizeControlUiBasePath } from "./control-ui-shared.js";
import type { ExecApprovalRecord } from "./exec-approval-manager.js";
import { APPROVALS_SCOPE } from "./method-scopes.js";
import { resolveOperatorRolePolicyForProfile } from "./operator-role-policy.js";
import { READ_SCOPE } from "./operator-scopes.js";
import { isApprovalRecordVisibleToClient } from "./server-methods/approval-record-lookup.js";
import type { GatewayClient } from "./server-methods/types.js";

const OPERATOR_ROLE = "operator";
const WEB_PUSH_APPROVAL_TIMEOUT_MS = 10_000;

type CurrentApprovalWebPushTarget = {
  subscription: BoundWebPushSubscription;
  scopes: string[];
  userProfileId: string | null;
};

function approvalWebPushUrl(cfg: OpenClawConfig, approvalId: string): string {
  const controlUiBasePath = normalizeControlUiBasePath(cfg.gateway?.controlUi?.basePath);
  // The receiving PWA owns the service-worker scope, which may differ from the
  // remote Gateway's base path. Keep navigation relative to that PWA scope.
  const approvalPath = `approve/${encodeURIComponent(approvalId)}`;
  const publicOrigin = resolveGatewayPublicOrigin(cfg);
  if (!publicOrigin) {
    return approvalPath;
  }
  const gatewayUrl = `${publicOrigin.replace(/^https:/u, "wss:").replace(/^http:/u, "ws:")}${controlUiBasePath}`;
  return `${approvalPath}#${new URLSearchParams({ gatewayUrl })}`;
}

function resolveCurrentApprovalTarget(params: {
  subscription: BoundWebPushSubscription;
  device: PairedDevice | undefined;
  cfg: OpenClawConfig;
}): CurrentApprovalWebPushTarget | null {
  const { device, subscription, cfg } = params;
  if (!device || !hasEffectivePairedDeviceRole(device, OPERATOR_ROLE)) {
    return null;
  }
  const operatorToken = device.tokens?.[OPERATOR_ROLE];
  if (!operatorToken || operatorToken.revokedAtMs) {
    return null;
  }
  const approvedScopes = device.approvedScopes ?? device.scopes;
  if (
    !approvedScopes ||
    !roleScopesAllow({
      role: OPERATOR_ROLE,
      requestedScopes: operatorToken.scopes,
      allowedScopes: approvedScopes,
    })
  ) {
    return null;
  }

  const storedProfileId = subscription.userProfileId;
  const userProfileId = storedProfileId ? (resolveUserProfileId(storedProfileId) ?? null) : null;
  if (storedProfileId && !userProfileId) {
    return null;
  }
  if (cfg.gateway?.roles && !userProfileId) {
    // A role boundary cannot recover which owner registered an old profile-less row.
    return null;
  }
  const rolePolicy = userProfileId
    ? resolveOperatorRolePolicyForProfile(userProfileId, cfg)
    : undefined;
  const allowedRoleScopes = rolePolicy ? new Set<string>(rolePolicy.scopes) : null;
  const scopes = allowedRoleScopes
    ? operatorToken.scopes.filter((scope) => allowedRoleScopes.has(scope))
    : [...operatorToken.scopes];
  if (
    !roleScopesAllow({
      role: OPERATOR_ROLE,
      requestedScopes: [APPROVALS_SCOPE, READ_SCOPE],
      allowedScopes: scopes,
    })
  ) {
    return null;
  }
  return { subscription, scopes, userProfileId };
}

function approvalWebPushClient(target: CurrentApprovalWebPushTarget): GatewayClient {
  const userProfileId = target.userProfileId;
  // Visibility owns only the authenticated identity, device, role, and scopes.
  // Complete inert handshake metadata keeps this projection inside the GatewayClient contract.
  return {
    connect: {
      minProtocol: 1,
      maxProtocol: 1,
      client: {
        id: GATEWAY_CLIENT_IDS.CONTROL_UI,
        version: "approval-web-push",
        platform: "web",
        mode: GATEWAY_CLIENT_MODES.WEBCHAT,
      },
      device: {
        id: target.subscription.deviceId,
        publicKey: "approval-web-push",
        signature: "approval-web-push",
        signedAt: 0,
        nonce: "approval-web-push",
      },
      role: OPERATOR_ROLE,
      scopes: target.scopes,
    },
    ...(userProfileId
      ? {
          authenticatedUserProfile: {
            profileId: userProfileId,
            displayName: null,
            hasAvatar: false,
            updatedAt: 0,
          },
        }
      : {}),
  };
}

async function deliverBoundApprovalWebPush<TPayload>(params: {
  record: ExecApprovalRecord<TPayload>;
  cfg: OpenClawConfig;
}): Promise<boolean> {
  if (params.record.resolvedAtMs !== undefined || params.record.expiresAtMs <= Date.now()) {
    return false;
  }
  const sendWebPushNotifications = await prepareWebPushNotificationSender();
  const pairing = await listDevicePairing();
  const pairedByDeviceId = new Map(pairing.paired.map((device) => [device.deviceId, device]));
  // Transport preparation may await module and key loading. Re-read both
  // binding and authority after it so no async gap remains before network I/O.
  const subscriptions = listBoundWebPushSubscriptions().filter((subscription) => {
    const target = resolveCurrentApprovalTarget({
      subscription,
      device: pairedByDeviceId.get(subscription.deviceId),
      cfg: params.cfg,
    });
    return Boolean(
      target &&
      isApprovalRecordVisibleToClient({
        record: params.record,
        client: approvalWebPushClient(target),
        cfg: params.cfg,
      }),
    );
  });
  if (subscriptions.length === 0) {
    return false;
  }

  // Transport and pairing preparation await. Terminal state and TTL belong to
  // the approval owner, so reread them with no async gap before network I/O.
  const now = Date.now();
  if (params.record.resolvedAtMs !== undefined || params.record.expiresAtMs <= now) {
    return false;
  }
  const ttlSeconds = Math.ceil((params.record.expiresAtMs - now) / 1_000);
  const results = await sendWebPushNotifications({
    subscriptions,
    payload: {
      title: "OpenClaw approval requested",
      body: "Open OpenClaw to review this request.",
      tag: `openclaw-approval-${params.record.id}`,
      url: approvalWebPushUrl(params.cfg, params.record.id),
    },
    // Approval prompts expire quickly and should not surface after the decision window.
    deliveryOptions: { TTL: ttlSeconds, urgency: "high", timeout: WEB_PUSH_APPROVAL_TIMEOUT_MS },
  });
  return results.some((result) => result.ok);
}

/** Sends a request notification only when at least one browser has a durable binding. */
export function deliverApprovalRequestWebPush<TPayload>(params: {
  record: ExecApprovalRecord<TPayload>;
  cfg: OpenClawConfig;
}): boolean | Promise<boolean> {
  const subscriptions = listBoundWebPushSubscriptions();
  return subscriptions.length === 0 ? false : deliverBoundApprovalWebPush(params);
}
