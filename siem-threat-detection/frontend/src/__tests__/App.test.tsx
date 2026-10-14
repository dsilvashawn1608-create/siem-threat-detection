import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "../App";

type Alert = {
  id: string;
  source: string;
  severity: string;
  status: string;
  signature: string;
  source_ip?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  incident_id?: string | null;
  created_at: string;
};

const baseAlerts: Alert[] = [
  {
    id: "alert-1",
    source: "snort",
    severity: "high",
    status: "new",
    signature: "Repeated probe",
    source_ip: "10.0.0.5",
    created_at: "2026-10-04T10:00:00Z",
  },
  {
    id: "alert-2",
    source: "splunk",
    severity: "low",
    status: "acknowledged",
    signature: "Login from new device",
    source_ip: "10.0.0.9",
    created_at: "2026-10-04T10:05:00Z",
  },
];

const baseIncidents = [
  {
    id: "incident-1",
    title: "Burst from 10.0.0.5",
    severity: "high",
    status: "open",
    assigned_to: null,
    created_at: "2026-10-04T10:01:00Z",
    resolved_at: null,
  },
];

const baseModels = [
  {
    id: "model-1",
    model_name: "isolation-forest-alert-features",
    version: "20261004T100000Z",
    training_samples: 12,
    is_active: true,
    trained_at: "2026-10-04T10:00:00Z",
  },
];

const baseConfigs = [
  {
    id: "config-1",
    name: "source_ip_burst",
    rule_type: "correlation",
    enabled: true,
    threshold: 3,
    description: "Opens an incident on repeated alerts from one source_ip.",
  },
];

function jsonResponse(body: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 200 ? "OK" : "Error",
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  } as Response);
}

type FetchFn = (url: string, init?: RequestInit) => Promise<Response>;

describe("App", () => {
  let fetchMock: ReturnType<typeof vi.fn<FetchFn>>;

  beforeEach(() => {
    fetchMock = vi.fn<FetchFn>((url, init) => {
      const method = init?.method ?? "GET";

      if (url.startsWith("/api/v1/alerts") && method === "GET") {
        return jsonResponse({ items: baseAlerts, total: baseAlerts.length });
      }
      if (url.startsWith("/api/v1/incidents") && method === "GET") {
        return jsonResponse({ items: baseIncidents, total: baseIncidents.length });
      }
      if (url === "/api/v1/ml/models") {
        return jsonResponse(baseModels);
      }
      if (url === "/api/v1/detection-configs" && method === "GET") {
        return jsonResponse(baseConfigs);
      }
      if (url.match(/\/api\/v1\/alerts\/alert-1/) && method === "PATCH") {
        return jsonResponse({ ...baseAlerts[0], status: "acknowledged" });
      }
      if (url === "/api/v1/incidents" && method === "POST") {
        return jsonResponse({ ...baseIncidents[0], id: "incident-new" }, 201);
      }
      if (url === "/api/v1/alerts" && method === "POST") {
        return jsonResponse({ ...baseAlerts[0], id: "alert-new" }, 201);
      }
      if (url === "/api/v1/incidents/correlate" && method === "POST") {
        return jsonResponse([]);
      }
      if (url.match(/\/api\/v1\/detection-configs\/config-1/) && method === "PATCH") {
        return jsonResponse({ ...baseConfigs[0], enabled: false });
      }

      return jsonResponse({}, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders the header and stat tiles reflecting fetched data", async () => {
    render(<App />);
    expect(screen.getByText("SIEM THREAT DETECTION PLATFORM")).toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText("New Alerts").nextSibling).toBeTruthy();
    });

    // One alert is "new" out of two total; one incident is open.
    const newAlertsTile = screen.getByText("New Alerts").parentElement!;
    expect(within(newAlertsTile).getByText("1")).toBeInTheDocument();

    const openIncidentsTile = screen.getByText("Open Incidents").parentElement!;
    expect(within(openIncidentsTile).getByText("1")).toBeInTheDocument();
  });

  it("shows the alerts table by default with both seeded alerts", async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("Repeated probe")).toBeInTheDocument();
    });
    expect(screen.getByText("Login from new device")).toBeInTheDocument();
  });

  it("filters the alerts table by free-text search", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    const search = screen.getByPlaceholderText("search signature / IP...");
    await user.type(search, "new device");

    expect(screen.queryByText("Repeated probe")).not.toBeInTheDocument();
    expect(screen.getByText("Login from new device")).toBeInTheDocument();
  });

  it("switches to the Incidents tab and shows seeded incidents", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "incidents" }));
    expect(screen.getByText("Burst from 10.0.0.5")).toBeInTheDocument();
  });

  it("switches to the Detection Configs tab and shows seeded configs", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Detection Configs" }));
    expect(screen.getByText("source_ip_burst")).toBeInTheDocument();
    expect(screen.getByText("ON")).toBeInTheDocument();
  });

  it("acknowledging a new alert PATCHes the alerts endpoint", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByText("ACK"));

    await waitFor(() => {
      const patchCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          url.includes("/alerts/alert-1") && init?.method === "PATCH"
      );
      expect(patchCall).toBeTruthy();
    });
  });

  it("opening the New Alert modal and submitting POSTs to /alerts", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByText("+ New Alert"));
    expect(screen.getByText("New Alert", { selector: "h2" })).toBeInTheDocument();

    const signatureInput = screen.getByPlaceholderText("e.g. Suspicious login pattern");
    await user.type(signatureInput, "Manual test signature");
    await user.click(screen.getByRole("button", { name: "Create Alert" }));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          url === "/api/v1/alerts" && init?.method === "POST"
      );
      expect(postCall).toBeTruthy();
      const body = JSON.parse((postCall![1] as RequestInit).body as string);
      expect(body.signature).toBe("Manual test signature");
    });
  });

  it("toggling a detection config PATCHes it", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Detection Configs" }));
    await user.click(screen.getByText("ON"));

    await waitFor(() => {
      const patchCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          url.includes("/detection-configs/config-1") && init?.method === "PATCH"
      );
      expect(patchCall).toBeTruthy();
      const body = JSON.parse((patchCall![1] as RequestInit).body as string);
      expect(body.enabled).toBe(false);
    });
  });

  it("escalating an alert to an incident POSTs /incidents with alert_ids", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByText("Repeated probe"));
    await user.click(screen.getByText("Escalate to Incident"));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          url === "/api/v1/incidents" && init?.method === "POST"
      );
      expect(postCall).toBeTruthy();
      const body = JSON.parse((postCall![1] as RequestInit).body as string);
      expect(body.alert_ids).toEqual(["alert-1"]);
    });
  });

  it("running correlation POSTs /incidents/correlate", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "incidents" }));
    await user.click(screen.getByText("Run Correlation"));

    await waitFor(() => {
      const postCall = fetchMock.mock.calls.find(
        ([url, init]) =>
          url === "/api/v1/incidents/correlate" && init?.method === "POST"
      );
      expect(postCall).toBeTruthy();
    });
  });
});
