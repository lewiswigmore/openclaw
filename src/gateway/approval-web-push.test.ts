import { expectDefined } from "@openclaw/normalization-core";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ExecApprovalManager } from "./exec-approval-manager.js";

const listDevicePairingMock = vi.fn();
const listBoundWebPushSubscriptionsMock = vi.fn();
const prepareWebPushNotificationSenderMock = vi.fn();
const preparedWebPushSendMock = vi.fn();
const resolveUserProfileIdMock = vi.fn();
const resolveOperatorRolePolicyForProfileMock = vi.fn();
const isApprovalRecordVisibleToClientMock = vi.fn();

vi.mock("../infra/device-pairing.js", async () => {
  const actual = await vi.importActual<typeof import("../infra/device-pairing.js")>(
    "../infra/device-pairing.js",
  );
  return { ...actual, listDevicePairing: listDevicePairingMock };
});

vi.mock("../infra/push-web.js", () => ({
  listBoundWebPushSubscriptions: listBoundWebPushSubscriptionsMock,
  prepareWebPushNotificationSender: prepareWebPushNotificationSenderMock,
}));

vi.mock("../state/user-profiles.js", () => ({
  resolveUserProfileId: resolveUserProfileIdMock,
}));

vi.mock("./operator-role-policy.js", async () => {
  const actual = await vi.importActual<typeof import("./operator-role-policy.js")>(
    "./operator-role-policy.js",
  );
  return {
    ...actual,
    resolveOperatorRolePolicyForProfile: resolveOperatorRolePolicyForProfileMock,
  };
});

vi.mock("./server-methods/approval-record-lookup.js", () => ({
  isApprovalRecordVisibleToClient: isApprovalRecordVisibleToClientMock,
}));

function pairedOperator(deviceId: string, scopes: string[]) {
  return {
    deviceId,
    publicKey: `public-${deviceId}`,
    role: "operator",
    roles: ["operator"],
    approvedScopes: scopes,
    createdAtMs: 1,
    approvedAtMs: 1,
    tokens: {
      operator: {
        token: `token-${deviceId}`,
        role: "operator",
        scopes,
        createdAtMs: 1,
      },
    },
  };
}

function boundSubscription(deviceId: string, userProfileId: string | null) {
  return {
    subscriptionId: `subscription-${deviceId}-${userProfileId ?? "owner"}`,
    endpoint: `https://push.example.test/${deviceId}/${userProfileId ?? "owner"}`,
    keys: { p256dh: `p256dh-${deviceId}`, auth: `auth-${deviceId}` },
    createdAtMs: 1,
    updatedAtMs: 1,
    deviceId,
    userProfileId,
  };
}

describe("approval Web Push delivery", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
    listDevicePairingMock.mockResolvedValue({ pending: [], paired: [] });
    listBoundWebPushSubscriptionsMock.mockReturnValue([]);
    prepareWebPushNotificationSenderMock.mockResolvedValue(preparedWebPushSendMock);
    preparedWebPushSendMock.mockResolvedValue([]);
    resolveUserProfileIdMock.mockImplementation((profileId: string) => profileId);
    resolveOperatorRolePolicyForProfileMock.mockReturnValue(undefined);
    isApprovalRecordVisibleToClientMock.mockImplementation(
      ({ record, client }) =>
        !record.requestedByDeviceId || record.requestedByDeviceId === client?.connect?.device?.id,
    );
  });

  it("sends a generic approval link only to currently authorized visible bindings", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const manager = new ExecApprovalManager();
    const record = manager.create({ command: "sensitive command" }, 60_000, "exec:approval.1");
    record.requestedByDeviceId = "allowed-device";
    const allowed = boundSubscription("allowed-device", "profile-allowed");
    const wrongDevice = boundSubscription("wrong-device", "profile-allowed");
    const missingScope = boundSubscription("missing-scope", "profile-allowed");
    const staleScope = boundSubscription("stale-scope", "profile-allowed");
    const staleScopeDevice = pairedOperator("stale-scope", ["operator.approvals", "operator.read"]);
    staleScopeDevice.approvedScopes = ["operator.read"];
    listBoundWebPushSubscriptionsMock.mockReturnValue([
      allowed,
      wrongDevice,
      missingScope,
      staleScope,
    ]);
    listDevicePairingMock.mockResolvedValue({
      pending: [],
      paired: [
        pairedOperator("allowed-device", ["operator.approvals", "operator.read"]),
        pairedOperator("wrong-device", ["operator.approvals", "operator.read"]),
        pairedOperator("missing-scope", ["operator.read"]),
        staleScopeDevice,
      ],
    });
    preparedWebPushSendMock.mockResolvedValue([
      { ok: true, subscriptionId: allowed.subscriptionId, statusCode: 201 },
    ]);

    const { deliverApprovalRequestWebPush } = await import("./approval-web-push.js");
    const delivered = deliverApprovalRequestWebPush({
      record,
      cfg: {
        gateway: {
          publicOrigin: "https://gateway.example.test",
          controlUi: { basePath: "/operator" },
        },
      },
    });

    await expect(delivered).resolves.toBe(true);
    expect(preparedWebPushSendMock).toHaveBeenCalledWith({
      subscriptions: [allowed],
      payload: {
        title: "OpenClaw approval requested",
        body: "Open OpenClaw to review this request.",
        tag: "openclaw-approval-exec:approval.1",
        url: "approve/exec%3Aapproval.1#gatewayUrl=wss%3A%2F%2Fgateway.example.test%2Foperator",
      },
      deliveryOptions: { TTL: 60, urgency: "high", timeout: 10_000 },
    });
    expect(JSON.stringify(preparedWebPushSendMock.mock.calls)).not.toContain("sensitive command");
  });

  it("rechecks the profile role and excludes unbound role-based subscriptions", async () => {
    const manager = new ExecApprovalManager();
    const record = manager.create({ command: "echo ok" }, 60_000, "exec:role-check");
    const current = boundSubscription("current-device", "profile-current");
    const downgraded = boundSubscription("downgraded-device", "profile-downgraded");
    const unboundProfile = boundSubscription("unbound-profile-device", null);
    listBoundWebPushSubscriptionsMock.mockReturnValue([current, downgraded, unboundProfile]);
    listDevicePairingMock.mockResolvedValue({
      pending: [],
      paired: [
        pairedOperator("current-device", ["operator.approvals", "operator.read"]),
        pairedOperator("downgraded-device", ["operator.approvals", "operator.read"]),
        pairedOperator("unbound-profile-device", ["operator.approvals", "operator.read"]),
      ],
    });
    resolveOperatorRolePolicyForProfileMock.mockImplementation((profileId: string) => ({
      sessions: { others: "none" },
      agents: [],
      scopes:
        profileId === "profile-current"
          ? ["operator.approvals", "operator.read"]
          : ["operator.read"],
    }));
    isApprovalRecordVisibleToClientMock.mockImplementation(
      ({ client }) => client?.authenticatedUserProfile?.profileId === "profile-current",
    );
    preparedWebPushSendMock.mockResolvedValue([
      { ok: true, subscriptionId: current.subscriptionId, statusCode: 201 },
    ]);

    const { deliverApprovalRequestWebPush } = await import("./approval-web-push.js");
    await expect(
      deliverApprovalRequestWebPush({
        record,
        cfg: {
          gateway: {
            roles: {
              definitions: {},
            },
          },
        },
      }),
    ).resolves.toBe(true);

    expect(preparedWebPushSendMock).toHaveBeenCalledWith(
      expect.objectContaining({ subscriptions: [current] }),
    );
  });

  it("prepares the transport before rereading current approval authority", async () => {
    const manager = new ExecApprovalManager();
    const record = manager.create({ command: "echo ok" }, 60_000, "exec:authority-race");
    const stale = boundSubscription("stale-device", "profile-stale");
    const current = boundSubscription("current-device", "profile-current");
    listBoundWebPushSubscriptionsMock.mockReturnValueOnce([stale]).mockReturnValueOnce([current]);
    listDevicePairingMock.mockResolvedValue({
      pending: [],
      paired: [pairedOperator("current-device", ["operator.approvals", "operator.read"])],
    });
    preparedWebPushSendMock.mockResolvedValue([
      { ok: true, subscriptionId: current.subscriptionId, statusCode: 201 },
    ]);

    const { deliverApprovalRequestWebPush } = await import("./approval-web-push.js");
    await expect(deliverApprovalRequestWebPush({ record, cfg: {} })).resolves.toBe(true);

    expect(prepareWebPushNotificationSenderMock).toHaveBeenCalledOnce();
    expect(
      expectDefined(
        prepareWebPushNotificationSenderMock.mock.invocationCallOrder[0],
        "transport preparation call order",
      ),
    ).toBeLessThan(
      expectDefined(listDevicePairingMock.mock.invocationCallOrder[0], "pairing read call order"),
    );
    expect(listBoundWebPushSubscriptionsMock).toHaveBeenCalledTimes(2);
    expect(preparedWebPushSendMock).toHaveBeenCalledWith(
      expect.objectContaining({ subscriptions: [current] }),
    );
  });

  it.each(["resolved", "expired"] as const)(
    "does not send after the approval becomes %s during transport preparation",
    async (terminalState) => {
      const manager = new ExecApprovalManager();
      const record = manager.create(
        { command: "echo ok" },
        60_000,
        `exec:${terminalState}-during-preparation`,
      );
      const current = boundSubscription("current-device", "profile-current");
      listBoundWebPushSubscriptionsMock.mockReturnValue([current]);
      listDevicePairingMock.mockResolvedValue({
        pending: [],
        paired: [pairedOperator("current-device", ["operator.approvals", "operator.read"])],
      });
      let finishPreparation: ((sender: typeof preparedWebPushSendMock) => void) | undefined;
      prepareWebPushNotificationSenderMock.mockReturnValueOnce(
        new Promise((resolve) => {
          finishPreparation = resolve;
        }),
      );

      const { deliverApprovalRequestWebPush } = await import("./approval-web-push.js");
      const delivery = deliverApprovalRequestWebPush({ record, cfg: {} });
      expect(prepareWebPushNotificationSenderMock).toHaveBeenCalledOnce();
      if (terminalState === "resolved") {
        record.resolvedAtMs = Date.now();
        record.status = "denied";
      } else {
        record.expiresAtMs = Date.now() - 1;
      }
      expectDefined(finishPreparation, "transport preparation resolver")(preparedWebPushSendMock);

      await expect(delivery).resolves.toBe(false);
      expect(preparedWebPushSendMock).not.toHaveBeenCalled();
    },
  );

  it("recomputes the remaining TTL after transport preparation", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const manager = new ExecApprovalManager();
    const record = manager.create({ command: "echo ok" }, 60_000, "exec:ttl-after-preparation");
    const current = boundSubscription("current-device", "profile-current");
    listBoundWebPushSubscriptionsMock.mockReturnValue([current]);
    listDevicePairingMock.mockResolvedValue({
      pending: [],
      paired: [pairedOperator("current-device", ["operator.approvals", "operator.read"])],
    });
    preparedWebPushSendMock.mockResolvedValue([
      { ok: true, subscriptionId: current.subscriptionId, statusCode: 201 },
    ]);
    let finishPreparation: ((sender: typeof preparedWebPushSendMock) => void) | undefined;
    prepareWebPushNotificationSenderMock.mockReturnValueOnce(
      new Promise((resolve) => {
        finishPreparation = resolve;
      }),
    );

    const { deliverApprovalRequestWebPush } = await import("./approval-web-push.js");
    const delivery = deliverApprovalRequestWebPush({ record, cfg: {} });
    expect(prepareWebPushNotificationSenderMock).toHaveBeenCalledOnce();
    vi.setSystemTime(31_000);
    expectDefined(finishPreparation, "transport preparation resolver")(preparedWebPushSendMock);

    await expect(delivery).resolves.toBe(true);
    expect(preparedWebPushSendMock).toHaveBeenCalledWith(
      expect.objectContaining({
        payload: expect.objectContaining({
          url: "approve/exec%3Attl-after-preparation",
        }),
        deliveryOptions: { TTL: 30, urgency: "high", timeout: 10_000 },
      }),
    );
  });
});
