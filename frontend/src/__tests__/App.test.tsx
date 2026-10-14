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
  let geminiAvailable: boolean;
  let simulationCreated: boolean;

  beforeEach(() => {
    geminiAvailable = true;
    simulationCreated = false;
    sessionStorage.setItem("siem_access_token", "test-token");
    fetchMock = vi.fn<FetchFn>((url, init) => {
      const method = init?.method ?? "GET";

      if (url === "/api/v1/auth/me") {
        return jsonResponse({ username: "test-admin", role: "admin" });
      }
      if (url === "/api/v1/ai/status") {
        return jsonResponse({ available: geminiAvailable, model: "gemini-2.5-flash" });
      }
      if (url === "/api/v1/ai/incidents/incident-1/analysis" && method === "POST") {
        return jsonResponse({
          resource_type: "incident",
          resource_id: "incident-1",
          model: "gemini-2.5-flash",
          generated_at: "2026-10-12T10:00:00Z",
          observed_evidence: { alert_count: 3, source_ip: "10.0.0.5" },
          ai_interpretation: "This may indicate repeated reconnaissance.",
          disclaimer: "AI-generated analysis is unverified.",
        });
      }
      if (url === "/api/v1/ai/simulations" && method === "POST") {
        simulationCreated = true;
        return jsonResponse(
          {
            simulation_id: "simulation-1",
            scenario: "port_scan",
            synthetic: true,
            alert_ids: ["sim-alert-1"],
            alerts_created: 4,
            incidents_created: 1,
            message: "Synthetic demo alerts were added. No real attack traffic was sent.",
          },
          201
        );
      }
      if (url === "/api/v1/auth/login" && method === "POST") {
        return jsonResponse({ access_token: "test-token", token_type: "bearer", expires_in: 28800 });
      }
      if (url.startsWith("/api/v1/alerts") && method === "GET") {
        const simulatedAlerts = simulationCreated
          ? [
              {
                ...baseAlerts[0],
                id: "sim-alert-1",
                signature: "[SIMULATION] simulated port-scan pattern",
                source_ip: "192.0.2.55",
              },
            ]
          : [];
        return jsonResponse({
          items: [...simulatedAlerts, ...baseAlerts],
          total: simulatedAlerts.length + baseAlerts.length,
        });
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
    sessionStorage.removeItem("siem_access_token");
    vi.unstubAllGlobals();
  });

  it("signs in before showing the console", async () => {
    sessionStorage.removeItem("siem_access_token");
    const user = userEvent.setup();
    render(<App />);
    await user.type(screen.getByLabelText("Username"), "test-admin");
    await user.type(screen.getByLabelText("Password"), "correct-password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "SIGN OUT" })).toBeInTheDocument()
    );
    const loginCall = fetchMock.mock.calls.find(
      ([url, init]) => url === "/api/v1/auth/login" && init?.method === "POST"
    );
    expect(loginCall).toBeTruthy();
    expect(JSON.parse((loginCall![1] as RequestInit).body as string)).toEqual({
      username: "test-admin",
      password: "correct-password",
    });
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

  it("shows optional Gemini incident analysis and separates it from SIEM evidence", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "incidents" }));
    await user.click(screen.getByText("Burst from 10.0.0.5"));
    await user.click(await screen.findByRole("button", { name: "Analyze with Gemini" }));

    expect(await screen.findByText("Observed SIEM evidence")).toBeInTheDocument();
    expect(screen.getByText("AI-generated interpretation (unverified)")).toBeInTheDocument();
    expect(screen.getByText("This may indicate repeated reconnaissance.")).toBeInTheDocument();
    expect(screen.getByText(/alert_count/)).toBeInTheDocument();
    expect(screen.getByText("AI-generated analysis is unverified.")).toBeInTheDocument();
  });

  it("explains when Gemini analysis is not configured", async () => {
    geminiAvailable = false;
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "incidents" }));
    await user.click(screen.getByText("Burst from 10.0.0.5"));

    expect(
      await screen.findByText(/AI analysis is unavailable\. An administrator can configure GEMINI_API_KEY/)
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Analyze with Gemini" })).not.toBeInTheDocument();
  });

  it("creates a synthetic SIEM demo from one prompt and shows the generated alert", async () => {
    const user = userEvent.setup();
    render(<App />);
    await waitFor(() => expect(screen.getByText("Repeated probe")).toBeInTheDocument());

    await user.click(screen.getByRole("button", { name: "Gemini Lab Simulation" }));
    const prompt = screen.getByLabelText("Describe a safe lab demo");
    await user.clear(prompt);
    await user.type(prompt, "Simulate a port scan in the lab");
    await user.click(screen.getByRole("button", { name: "Create synthetic SIEM demo" }));

    expect(
      await screen.findByText("[SIMULATION] simulated port-scan pattern")
    ).toBeInTheDocument();
    expect(screen.getByText(/No real traffic was sent/)).toBeInTheDocument();
    const simulationCall = fetchMock.mock.calls.find(
      ([url, init]) => url === "/api/v1/ai/simulations" && init?.method === "POST"
    );
    expect(simulationCall).toBeTruthy();
    expect(JSON.parse((simulationCall![1] as RequestInit).body as string)).toEqual({
      prompt: "Simulate a port scan in the lab",
    });
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
