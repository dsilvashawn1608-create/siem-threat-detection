import { useEffect, useMemo, useState, useCallback } from "react";
import type { FormEvent, ReactNode } from "react";
import { StatusDot } from "./components/StatusDot";
import { ConsoleField } from "./components/ConsoleField";
import { Modal, FormField, inputClass } from "./components/Modal";

const API_BASE = "/api/v1";
const TOKEN_KEY = "siem_access_token";

type Alert = {
  id: string;
  source: string;
  severity: string;
  status: string;
  signature: string;
  category?: string | null;
  source_ip?: string | null;
  dest_ip?: string | null;
  dest_port?: number | null;
  incident_id?: string | null;
  created_at: string;
};

type Incident = {
  id: string;
  title: string;
  description?: string | null;
  severity: string;
  status: string;
  assigned_to?: string | null;
  created_at: string;
  resolved_at?: string | null;
};

type MLModel = {
  id: string;
  model_name: string;
  version: string;
  training_samples?: number | null;
  is_active: boolean;
  trained_at: string;
};

type DetectionConfig = {
  id: string;
  name: string;
  rule_type: string;
  enabled: boolean;
  threshold?: number | null;
  description?: string | null;
};

type AIAnalysis = {
  resource_type: "alert" | "incident";
  resource_id: string;
  model: string;
  generated_at: string;
  observed_evidence: Record<string, unknown>;
  ai_interpretation: string;
  disclaimer: string;
};

type AISimulation = {
  simulation_id: string;
  scenario: "port_scan" | "failed_logins" | "web_probe";
  synthetic: true;
  alert_ids: string[];
  alerts_created: number;
  incidents_created: number;
  message: string;
};

type Tab = "alerts" | "incidents" | "ml" | "configs";

const SEVERITIES = ["low", "medium", "high", "critical"] as const;
const ALERT_SOURCES = ["snort", "splunk", "ml_anomaly", "manual"] as const;
const ALERT_STATUSES = ["new", "acknowledged", "escalated", "closed", "false_positive"] as const;
const INCIDENT_STATUSES = ["open", "investigating", "contained", "resolved", "closed"] as const;
const RULE_TYPES = ["snort_rule", "ml_threshold", "splunk_search", "correlation"] as const;

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const token = sessionStorage.getItem(TOKEN_KEY);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const resp = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });
  if (!resp.ok) {
    const text = await resp.text();
    let message = text;
    try {
      const body = JSON.parse(text) as { detail?: unknown };
      if (typeof body.detail === "string") message = body.detail;
    } catch {
      // Keep non-JSON provider and proxy error bodies readable as-is.
    }
    throw new Error(`${resp.status} ${resp.statusText}: ${message}`);
  }
  return resp.json();
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(
    () => Boolean(sessionStorage.getItem(TOKEN_KEY))
  );
  const [authUser, setAuthUser] = useState<{ username: string; role: string } | null>(null);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);
  const [tab, setTab] = useState<Tab>("alerts");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [models, setModels] = useState<MLModel[]>([]);
  const [configs, setConfigs] = useState<DetectionConfig[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [aiAvailable, setAiAvailable] = useState<boolean | null>(null);
  const [aiModel, setAiModel] = useState<string | null>(null);
  const [aiAvailabilityError, setAiAvailabilityError] = useState<string | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysis | null>(null);
  const [aiAnalysisError, setAiAnalysisError] = useState<string | null>(null);
  const [aiAnalysisErrorKey, setAiAnalysisErrorKey] = useState<string | null>(null);
  const [aiAnalysisLoadingKey, setAiAnalysisLoadingKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const [showNewAlert, setShowNewAlert] = useState(false);
  const [showNewIncident, setShowNewIncident] = useState(false);
  const [showNewConfig, setShowNewConfig] = useState(false);
  const [showSimulation, setShowSimulation] = useState(false);
  const [simulationLoading, setSimulationLoading] = useState(false);
  const [simulationError, setSimulationError] = useState<string | null>(null);

  // --- Alert filters ---
  const [alertSource, setAlertSource] = useState<string>("");
  const [alertSeverity, setAlertSeverity] = useState<string>("");
  const [alertStatus, setAlertStatus] = useState<string>("");
  const [alertSearch, setAlertSearch] = useState<string>("");

  // --- Incident filters ---
  const [incidentSeverity, setIncidentSeverity] = useState<string>("");
  const [incidentStatus, setIncidentStatus] = useState<string>("");

  const refresh = useCallback(async () => {
    if (!authenticated) return;
    setLoading(true);
    setError(null);
    try {
      const [alertsResp, incidentsResp, modelsResp, configsResp] = await Promise.all([
        fetchJSON<{ items: Alert[]; total: number }>("/alerts?limit=200"),
        fetchJSON<{ items: Incident[]; total: number }>("/incidents?limit=200"),
        fetchJSON<MLModel[]>("/ml/models").catch(() => []),
        fetchJSON<DetectionConfig[]>("/detection-configs").catch(() => []),
      ]);
      setAlerts(alertsResp.items);
      setIncidents(incidentsResp.items);
      setModels(modelsResp);
      setConfigs(configsResp);
      setLastRefreshed(new Date());
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      if (err instanceof Error && err.message.startsWith("401 ")) {
        sessionStorage.removeItem(TOKEN_KEY);
        setAuthenticated(false);
        setAuthUser(null);
      }
    } finally {
      setLoading(false);
    }
  }, [authenticated]);

  useEffect(() => {
    if (!authenticated) return;
    fetchJSON<{ available: boolean; model: string }>("/ai/status")
      .then(({ available, model }) => {
        setAiAvailable(available);
        setAiModel(model);
        setAiAvailabilityError(null);
      })
      .catch(() => {
        setAiAvailable(null);
        setAiModel(null);
        setAiAvailabilityError("Could not check Gemini availability. Refresh and try again.");
      });
    fetchJSON<{ username: string; role: string }>("/auth/me")
      .then(setAuthUser)
      .catch(() => {
        sessionStorage.removeItem(TOKEN_KEY);
        setAuthenticated(false);
        setAuthUser(null);
      });
    refresh();
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [authenticated, refresh]);

  async function login(username: string, password: string) {
    setLoggingIn(true);
    setLoginError(null);
    try {
      const result = await fetchJSON<{ access_token: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      sessionStorage.setItem(TOKEN_KEY, result.access_token);
      setAuthenticated(true);
    } catch (err) {
      setLoginError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setLoggingIn(false);
    }
  }

  function logout() {
    sessionStorage.removeItem(TOKEN_KEY);
    setAuthenticated(false);
    setAuthUser(null);
    setAlerts([]);
    setIncidents([]);
    setModels([]);
    setConfigs([]);
    setAiAnalysis(null);
    setAiAnalysisError(null);
    setAiAnalysisErrorKey(null);
    setAiAvailable(null);
    setAiModel(null);
  }

  async function requestAIAnalysis(resourceType: "alert" | "incident", resourceId: string) {
    const key = `${resourceType}:${resourceId}`;
    setAiAnalysisLoadingKey(key);
    setAiAnalysisError(null);
    setAiAnalysisErrorKey(null);
    setAiAnalysis(null);
    try {
      const result = await fetchJSON<AIAnalysis>(
        `/ai/${resourceType === "alert" ? "alerts" : "incidents"}/${resourceId}/analysis`,
        { method: "POST" }
      );
      setAiAnalysis(result);
    } catch (err) {
      setAiAnalysisErrorKey(key);
      setAiAnalysisError(
        err instanceof Error ? err.message : "AI analysis failed. Please try again."
      );
    } finally {
      setAiAnalysisLoadingKey(null);
    }
  }

  async function requestAISimulation(prompt: string) {
    setSimulationLoading(true);
    setSimulationError(null);
    try {
      const result = await fetchJSON<AISimulation>("/ai/simulations", {
        method: "POST",
        body: JSON.stringify({ prompt }),
      });
      setShowSimulation(false);
      setTab("alerts");
      setAlertSearch("[SIMULATION]");
      setActionMessage(
        `Synthetic ${result.scenario.replace(/_/g, " ")} demo: ${result.alerts_created} alert(s), ${result.incidents_created} incident(s). No real traffic was sent.`
      );
      await refresh();
    } catch (err) {
      setSimulationError(
        err instanceof Error ? err.message : "Simulation failed. Please try again."
      );
    } finally {
      setSimulationLoading(false);
    }
  }

  const openCount = useMemo(
    () => incidents.filter((i) => i.status === "open" || i.status === "investigating").length,
    [incidents]
  );
  const newAlertCount = useMemo(
    () => alerts.filter((a) => a.status === "new").length,
    [alerts]
  );
  const activeModel = useMemo(() => models.find((m) => m.is_active) ?? null, [models]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((a) => {
      if (alertSource && a.source !== alertSource) return false;
      if (alertSeverity && a.severity !== alertSeverity) return false;
      if (alertStatus && a.status !== alertStatus) return false;
      if (alertSearch) {
        const needle = alertSearch.toLowerCase();
        const haystack = `${a.signature} ${a.source_ip ?? ""} ${a.dest_ip ?? ""}`.toLowerCase();
        if (!haystack.includes(needle)) return false;
      }
      return true;
    });
  }, [alerts, alertSource, alertSeverity, alertStatus, alertSearch]);

  const filteredIncidents = useMemo(() => {
    return incidents.filter((i) => {
      if (incidentSeverity && i.severity !== incidentSeverity) return false;
      if (incidentStatus && i.status !== incidentStatus) return false;
      return true;
    });
  }, [incidents, incidentSeverity, incidentStatus]);

  if (!authenticated) {
    return <LoginScreen onLogin={login} error={loginError} submitting={loggingIn} />;
  }

  async function runAction(label: string, fn: () => Promise<unknown>) {
    setActionMessage(`${label}...`);
    try {
      await fn();
      setActionMessage(`${label}: done`);
      await refresh();
    } catch (err) {
      setActionMessage(`${label}: failed — ${err instanceof Error ? err.message : "error"}`);
    }
  }

  async function acknowledgeAlert(alert: Alert) {
    await runAction(`Acknowledge ${alert.id.slice(0, 8)}`, () =>
      fetchJSON(`/alerts/${alert.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: "acknowledged" }),
      })
    );
  }

  async function escalateAlertToIncident(alert: Alert) {
    await runAction(`Escalate ${alert.id.slice(0, 8)} to incident`, async () => {
      await fetchJSON("/incidents", {
        method: "POST",
        body: JSON.stringify({
          title: `Manual escalation: ${alert.signature}`,
          severity: alert.severity,
          alert_ids: [alert.id],
        }),
      });
      setSelectedAlert(null);
    });
  }

  async function resolveIncident(incident: Incident) {
    await runAction(`Resolve ${incident.id.slice(0, 8)}`, () =>
      fetchJSON(`/incidents/${incident.id}`, {
        method: "PATCH",
        body: JSON.stringify({ status: "resolved" }),
      })
    );
  }

  async function runCorrelation() {
    await runAction("Run correlation", async () => {
      const created = await fetchJSON<Incident[]>("/incidents/correlate", { method: "POST" });
      setActionMessage(`Correlation run: ${created.length} new incident(s) created.`);
    });
  }

  async function toggleConfig(config: DetectionConfig) {
    await runAction(`Toggle ${config.name}`, () =>
      fetchJSON(`/detection-configs/${config.id}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: !config.enabled }),
      })
    );
  }

  return (
    <div className="min-h-screen bg-console-bg text-console-text flex flex-col">
      <header className="border-b border-console-border px-6 py-4 flex items-center justify-between">
        <div className="flex items-baseline gap-3">
          <h1 className="text-lg font-semibold text-console-accent tracking-wide">
            SIEM THREAT DETECTION PLATFORM
          </h1>
          <span className="text-console-dim text-xs">// SOC console</span>
        </div>
        <div className="flex items-center gap-6 text-xs">
          <span className="text-console-dim">
            {authUser ? `${authUser.username} · ${authUser.role}` : "checking session..."}
          </span>
          <span className="text-console-dim">
            {lastRefreshed ? `last sync ${lastRefreshed.toLocaleTimeString()}` : "syncing..."}
          </span>
          <button
            onClick={() => refresh()}
            className="border border-console-border rounded px-3 py-1 hover:border-console-accent hover:text-console-accent transition-colors"
          >
            {loading ? "REFRESHING" : "REFRESH"}
          </button>
          <button
            onClick={logout}
            className="border border-console-border rounded px-3 py-1 hover:border-console-crit hover:text-console-crit transition-colors"
          >
            SIGN OUT
          </button>
        </div>
      </header>

      <section className="grid grid-cols-4 gap-px bg-console-border border-b border-console-border">
        <StatTile label="New Alerts" value={newAlertCount} tone="high" />
        <StatTile label="Open Incidents" value={openCount} tone="crit" />
        <StatTile label="Total Alerts" value={alerts.length} tone="low" />
        <StatTile
          label="Active ML Model"
          value={activeModel ? activeModel.version.slice(0, 15) : "none trained"}
          tone="accent"
        />
      </section>

      {error && (
        <div className="bg-console-crit/10 border-b border-console-crit text-console-crit text-sm px-6 py-2">
          {error}
        </div>
      )}
      {actionMessage && (
        <div className="bg-console-panel border-b border-console-border text-console-accent text-xs px-6 py-1.5">
          {actionMessage}
        </div>
      )}

      <nav className="flex items-center justify-between px-6 pt-4">
        <div className="flex gap-1">
          {(["alerts", "incidents", "ml", "configs"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-4 py-2 text-xs uppercase tracking-wider border-b-2 transition-colors ${
                tab === t
                  ? "border-console-accent text-console-accent"
                  : "border-transparent text-console-dim hover:text-console-text"
              }`}
            >
              {t === "configs" ? "Detection Configs" : t}
            </button>
          ))}
        </div>
        <div className="flex gap-2 pb-2">
          {tab === "alerts" && (
            <>
              {authUser?.role === "admin" && aiAvailable && (
                <SmallButton onClick={() => setShowSimulation(true)}>
                  Gemini Lab Simulation
                </SmallButton>
              )}
              <SmallButton onClick={() => setShowNewAlert(true)}>+ New Alert</SmallButton>
            </>
          )}
          {tab === "incidents" && (
            <>
              <SmallButton onClick={runCorrelation}>Run Correlation</SmallButton>
              <SmallButton onClick={() => setShowNewIncident(true)}>+ New Incident</SmallButton>
            </>
          )}
          {tab === "configs" && authUser?.role === "admin" && (
            <SmallButton onClick={() => setShowNewConfig(true)}>+ New Config</SmallButton>
          )}
        </div>
      </nav>

      {tab === "alerts" && (
        <FilterBar>
          <SelectFilter label="Source" value={alertSource} onChange={setAlertSource} options={ALERT_SOURCES} />
          <SelectFilter label="Severity" value={alertSeverity} onChange={setAlertSeverity} options={SEVERITIES} />
          <SelectFilter label="Status" value={alertStatus} onChange={setAlertStatus} options={ALERT_STATUSES} />
          <input
            value={alertSearch}
            onChange={(e) => setAlertSearch(e.target.value)}
            placeholder="search signature / IP..."
            className={`${inputClass} w-56`}
          />
          <span className="text-console-dim text-xs ml-auto self-center">
            {filteredAlerts.length} / {alerts.length}
          </span>
        </FilterBar>
      )}
      {tab === "incidents" && (
        <FilterBar>
          <SelectFilter label="Severity" value={incidentSeverity} onChange={setIncidentSeverity} options={SEVERITIES} />
          <SelectFilter label="Status" value={incidentStatus} onChange={setIncidentStatus} options={INCIDENT_STATUSES} />
          <span className="text-console-dim text-xs ml-auto self-center">
            {filteredIncidents.length} / {incidents.length}
          </span>
        </FilterBar>
      )}

      <main className="flex-1 flex gap-4 px-6 pb-6 pt-2 min-h-0">
        <div className="flex-1 min-h-0 overflow-auto border border-console-border rounded">
          {tab === "alerts" && (
            <AlertsTable
              alerts={filteredAlerts}
              onSelect={setSelectedAlert}
              onAcknowledge={acknowledgeAlert}
            />
          )}
          {tab === "incidents" && (
            <IncidentsTable
              incidents={filteredIncidents}
              onSelect={setSelectedIncident}
              onResolve={resolveIncident}
            />
          )}
          {tab === "ml" && (
            <MLPanel models={models} onTrain={refresh} canTrain={authUser?.role === "admin"} />
          )}
          {tab === "configs" && (
            <ConfigsPanel
              configs={configs}
              onToggle={toggleConfig}
              canEdit={authUser?.role === "admin"}
            />
          )}
        </div>

        {tab === "alerts" && selectedAlert && (
          <DetailPanel title="Alert Detail" onClose={() => setSelectedAlert(null)}>
            <ConsoleField label="ID" value={selectedAlert.id} />
            <ConsoleField label="Source" value={selectedAlert.source} />
            <ConsoleField
              label="Severity"
              value={<StatusDot severity={selectedAlert.severity} />}
            />
            <ConsoleField label="Status" value={selectedAlert.status} />
            <ConsoleField label="Signature" value={selectedAlert.signature} />
            <ConsoleField label="Category" value={selectedAlert.category ?? "—"} />
            <ConsoleField label="Source IP" value={selectedAlert.source_ip ?? "—"} />
            <ConsoleField
              label="Dest"
              value={
                selectedAlert.dest_ip
                  ? `${selectedAlert.dest_ip}${
                      selectedAlert.dest_port ? ":" + selectedAlert.dest_port : ""
                    }`
                  : "—"
              }
            />
            <ConsoleField label="Incident" value={selectedAlert.incident_id ?? "unassigned"} />
            <ConsoleField
              label="Created"
              value={new Date(selectedAlert.created_at).toLocaleString()}
            />
            <AIAnalysisPanel
              available={aiAvailable}
              model={aiModel}
              availabilityError={aiAvailabilityError}
              loading={aiAnalysisLoadingKey === `alert:${selectedAlert.id}`}
              result={
                aiAnalysis?.resource_type === "alert" &&
                aiAnalysis.resource_id === selectedAlert.id
                  ? aiAnalysis
                  : null
              }
              error={aiAnalysisErrorKey === `alert:${selectedAlert.id}` ? aiAnalysisError : null}
              onAnalyze={() => requestAIAnalysis("alert", selectedAlert.id)}
            />
            {!selectedAlert.incident_id && (
              <button
                onClick={() => escalateAlertToIncident(selectedAlert)}
                className="mt-2 border border-console-border rounded px-3 py-1.5 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors"
              >
                Escalate to Incident
              </button>
            )}
          </DetailPanel>
        )}

        {tab === "incidents" && selectedIncident && (
          <DetailPanel title="Incident Detail" onClose={() => setSelectedIncident(null)}>
            <ConsoleField label="ID" value={selectedIncident.id} />
            <ConsoleField label="Title" value={selectedIncident.title} />
            <ConsoleField
              label="Severity"
              value={<StatusDot severity={selectedIncident.severity} />}
            />
            <ConsoleField label="Status" value={selectedIncident.status} />
            <ConsoleField label="Assigned To" value={selectedIncident.assigned_to ?? "unassigned"} />
            <ConsoleField label="Description" value={selectedIncident.description ?? "—"} />
            <ConsoleField
              label="Created"
              value={new Date(selectedIncident.created_at).toLocaleString()}
            />
            <ConsoleField
              label="Resolved"
              value={
                selectedIncident.resolved_at
                  ? new Date(selectedIncident.resolved_at).toLocaleString()
                  : "—"
              }
            />
            <AIAnalysisPanel
              available={aiAvailable}
              model={aiModel}
              availabilityError={aiAvailabilityError}
              loading={aiAnalysisLoadingKey === `incident:${selectedIncident.id}`}
              result={
                aiAnalysis?.resource_type === "incident" &&
                aiAnalysis.resource_id === selectedIncident.id
                  ? aiAnalysis
                  : null
              }
              error={
                aiAnalysisErrorKey === `incident:${selectedIncident.id}`
                  ? aiAnalysisError
                  : null
              }
              onAnalyze={() => requestAIAnalysis("incident", selectedIncident.id)}
            />
          </DetailPanel>
        )}
      </main>

      {showNewAlert && (
        <NewAlertModal
          onClose={() => setShowNewAlert(false)}
          onCreate={async (payload) => {
            await runAction("Create alert", () =>
              fetchJSON("/alerts", { method: "POST", body: JSON.stringify(payload) })
            );
            setShowNewAlert(false);
          }}
        />
      )}
      {showNewIncident && (
        <NewIncidentModal
          onClose={() => setShowNewIncident(false)}
          onCreate={async (payload) => {
            await runAction("Create incident", () =>
              fetchJSON("/incidents", { method: "POST", body: JSON.stringify(payload) })
            );
            setShowNewIncident(false);
          }}
        />
      )}
      {showSimulation && (
        <SimulationModal
          onClose={() => {
            setShowSimulation(false);
            setSimulationError(null);
          }}
          onSubmit={requestAISimulation}
          loading={simulationLoading}
          error={simulationError}
        />
      )}
      {showNewConfig && (
        <NewConfigModal
          onClose={() => setShowNewConfig(false)}
          onCreate={async (payload) => {
            await runAction("Create detection config", () =>
              fetchJSON("/detection-configs", { method: "POST", body: JSON.stringify(payload) })
            );
            setShowNewConfig(false);
          }}
        />
      )}
    </div>
  );
}

function LoginScreen({
  onLogin,
  error,
  submitting,
}: {
  onLogin: (username: string, password: string) => Promise<void>;
  error: string | null;
  submitting: boolean;
}) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void onLogin(username, password);
  }

  return (
    <main className="min-h-screen bg-console-bg text-console-text flex items-center justify-center px-6">
      <form onSubmit={submit} className="w-full max-w-sm border border-console-border rounded p-6 flex flex-col gap-4">
        <h1 className="text-console-accent text-sm font-semibold tracking-wide">
          SIEM THREAT DETECTION PLATFORM
        </h1>
        <p className="text-console-dim text-xs">Sign in to the SOC console</p>
        <label className="text-xs text-console-dim flex flex-col gap-1">
          Username
          <input
            autoComplete="username"
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            className={inputClass}
          />
        </label>
        <label className="text-xs text-console-dim flex flex-col gap-1">
          Password
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className={inputClass}
          />
        </label>
        {error && <p role="alert" className="text-console-crit text-xs">{error}</p>}
        <button
          type="submit"
          disabled={submitting}
          className="border border-console-accent text-console-accent rounded px-4 py-2 text-xs uppercase tracking-wider disabled:opacity-50"
        >
          {submitting ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </main>
  );
}

function StatTile({
  label,
  value,
  tone,
}: {
  label: string;
  value: string | number;
  tone: "crit" | "high" | "low" | "accent";
}) {
  const toneClass =
    tone === "crit"
      ? "text-console-crit"
      : tone === "high"
      ? "text-console-high"
      : tone === "accent"
      ? "text-console-accent"
      : "text-console-low";
  return (
    <div className="bg-console-panel px-6 py-4 flex flex-col gap-1">
      <span className="text-[10px] uppercase tracking-widest text-console-dim">{label}</span>
      <span className={`text-2xl font-semibold ${toneClass}`}>{value}</span>
    </div>
  );
}

function SmallButton({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="border border-console-border rounded px-3 py-1.5 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors"
    >
      {children}
    </button>
  );
}

function FilterBar({ children }: { children: ReactNode }) {
  return <div className="flex items-end gap-3 px-6 pt-3">{children}</div>;
}

function SelectFilter({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: readonly string[];
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] uppercase tracking-widest text-console-dim">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={`${inputClass} py-1`}
      >
        <option value="">all</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
          </option>
        ))}
      </select>
    </label>
  );
}

function AlertsTable({
  alerts,
  onSelect,
  onAcknowledge,
}: {
  alerts: Alert[];
  onSelect: (a: Alert) => void;
  onAcknowledge: (a: Alert) => void;
}) {
  if (alerts.length === 0) {
    return <EmptyState message="No alerts match the current filters." />;
  }
  return (
    <table className="w-full text-xs">
      <thead className="bg-console-panel sticky top-0 text-console-dim uppercase tracking-wider">
        <tr className="text-left">
          <Th>Severity</Th>
          <Th>Status</Th>
          <Th>Source</Th>
          <Th>Signature</Th>
          <Th>Source IP</Th>
          <Th>Created</Th>
          <Th />
        </tr>
      </thead>
      <tbody>
        {alerts.map((a) => (
          <tr
            key={a.id}
            className="border-t border-console-border hover:bg-console-panel/60 cursor-pointer"
            onClick={() => onSelect(a)}
          >
            <Td>
              <StatusDot severity={a.severity} />
            </Td>
            <Td>{a.status}</Td>
            <Td className="uppercase">{a.source}</Td>
            <Td className="max-w-sm truncate">{a.signature}</Td>
            <Td>{a.source_ip ?? "—"}</Td>
            <Td>{new Date(a.created_at).toLocaleTimeString()}</Td>
            <Td>
              {a.status === "new" && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onAcknowledge(a);
                  }}
                  className="text-console-accent hover:underline"
                >
                  ACK
                </button>
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function IncidentsTable({
  incidents,
  onSelect,
  onResolve,
}: {
  incidents: Incident[];
  onSelect: (i: Incident) => void;
  onResolve: (i: Incident) => void;
}) {
  if (incidents.length === 0) {
    return (
      <EmptyState message="No incidents match the current filters. The correlation engine opens one once a source_ip crosses the alert-burst threshold." />
    );
  }
  return (
    <table className="w-full text-xs">
      <thead className="bg-console-panel sticky top-0 text-console-dim uppercase tracking-wider">
        <tr className="text-left">
          <Th>Severity</Th>
          <Th>Status</Th>
          <Th>Title</Th>
          <Th>Assigned</Th>
          <Th>Created</Th>
          <Th />
        </tr>
      </thead>
      <tbody>
        {incidents.map((i) => (
          <tr
            key={i.id}
            className="border-t border-console-border hover:bg-console-panel/60 cursor-pointer"
            onClick={() => onSelect(i)}
          >
            <Td>
              <StatusDot severity={i.severity} />
            </Td>
            <Td>{i.status}</Td>
            <Td className="max-w-sm truncate">{i.title}</Td>
            <Td>{i.assigned_to ?? "—"}</Td>
            <Td>{new Date(i.created_at).toLocaleTimeString()}</Td>
            <Td>
              {i.status !== "resolved" && i.status !== "closed" && (
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onResolve(i);
                  }}
                  className="text-console-accent hover:underline"
                >
                  RESOLVE
                </button>
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function MLPanel({
  models,
  onTrain,
  canTrain,
}: {
  models: MLModel[];
  onTrain: () => Promise<void>;
  canTrain: boolean;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  async function train() {
    setBusy("train");
    setMessage(null);
    try {
      const result = await fetchJSON<{ training_samples: number }>("/ml/train", {
        method: "POST",
      });
      setMessage(`Trained on ${result.training_samples} source_ip samples.`);
      await onTrain();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Training failed");
    } finally {
      setBusy(null);
    }
  }

  async function scoreAndAlert() {
    setBusy("score");
    setMessage(null);
    try {
      const created = await fetchJSON<string[]>("/ml/score-and-alert", { method: "POST" });
      setMessage(`Scoring complete — ${created.length} new anomaly alert(s) created.`);
      await onTrain();
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Scoring failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="p-6 flex flex-col gap-4">
      {canTrain ? (
        <div className="flex gap-3">
          <button
            onClick={train}
            disabled={busy !== null}
            className="border border-console-border rounded px-4 py-2 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
          >
            {busy === "train" ? "Training..." : "Train Isolation Forest"}
          </button>
          <button
            onClick={scoreAndAlert}
            disabled={busy !== null}
            className="border border-console-border rounded px-4 py-2 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
          >
            {busy === "score" ? "Scoring..." : "Score & Create Anomaly Alerts"}
          </button>
        </div>
      ) : (
        <p className="text-console-dim text-xs">Training and alert generation require an admin account.</p>
      )}
      {message && <p className="text-xs text-console-accent">{message}</p>}

      <table className="w-full text-xs mt-2">
        <thead className="text-console-dim uppercase tracking-wider">
          <tr className="text-left">
            <Th>Version</Th>
            <Th>Samples</Th>
            <Th>Trained At</Th>
            <Th>Active</Th>
          </tr>
        </thead>
        <tbody>
          {models.map((m) => (
            <tr key={m.id} className="border-t border-console-border">
              <Td>{m.version}</Td>
              <Td>{m.training_samples ?? "—"}</Td>
              <Td>{new Date(m.trained_at).toLocaleString()}</Td>
              <Td>{m.is_active ? "ACTIVE" : ""}</Td>
            </tr>
          ))}
        </tbody>
      </table>
      {models.length === 0 && (
        <EmptyState message="No models trained yet. Ingest at least ml_min_training_samples worth of source_ip activity, then train." />
      )}
    </div>
  );
}

function ConfigsPanel({
  configs,
  onToggle,
  canEdit,
}: {
  configs: DetectionConfig[];
  onToggle: (c: DetectionConfig) => void;
  canEdit: boolean;
}) {
  if (configs.length === 0) {
    return <EmptyState message="No detection configs yet." />;
  }
  return (
    <table className="w-full text-xs">
      <thead className="bg-console-panel sticky top-0 text-console-dim uppercase tracking-wider">
        <tr className="text-left">
          <Th>Name</Th>
          <Th>Rule Type</Th>
          <Th>Threshold</Th>
          <Th>Description</Th>
          <Th>Enabled</Th>
        </tr>
      </thead>
      <tbody>
        {configs.map((c) => (
          <tr key={c.id} className="border-t border-console-border">
            <Td className="font-medium">{c.name}</Td>
            <Td className="uppercase">{c.rule_type}</Td>
            <Td>{c.threshold ?? "—"}</Td>
            <Td className="max-w-md truncate">{c.description ?? "—"}</Td>
            <Td>
              {canEdit ? (
                <button
                  onClick={() => onToggle(c)}
                  className={`px-2 py-0.5 rounded border text-xs uppercase tracking-wider transition-colors ${
                    c.enabled
                      ? "border-console-accent text-console-accent"
                      : "border-console-border text-console-dim"
                  }`}
                >
                  {c.enabled ? "ON" : "OFF"}
                </button>
              ) : (
                <span>{c.enabled ? "ON" : "OFF"}</span>
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function SimulationModal({
  onClose,
  onSubmit,
  loading,
  error,
}: {
  onClose: () => void;
  onSubmit: (prompt: string) => Promise<void>;
  loading: boolean;
  error: string | null;
}) {
  const [prompt, setPrompt] = useState("Simulate a port scan in the lab");

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    await onSubmit(prompt.trim());
  }

  return (
    <Modal title="Gemini lab simulation" onClose={onClose}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <p className="text-xs text-console-dim">
          Gemini selects only a predefined demo scenario. The backend creates
          clearly marked synthetic SIEM alerts using documentation-only IP
          addresses; it does not send packets, attempt logins, or target any host.
          Admin access and a configured Gemini key are required.
        </p>
        <FormField label="Describe a safe lab demo">
          <textarea
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            maxLength={500}
            minLength={3}
            rows={3}
            required
            className={`${inputClass} resize-y`}
          />
        </FormField>
        <p className="text-xs text-console-dim">
          Supported: simulated port scan, repeated SSH login failures, or benign
          web probe. Requests outside these scenarios are rejected.
        </p>
        {error && (
          <p role="alert" className="text-xs text-console-crit">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={loading || prompt.trim().length < 3}
          className="border border-console-border rounded px-3 py-2 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
        >
          {loading ? "Classifying and creating demo..." : "Create synthetic SIEM demo"}
        </button>
      </form>
    </Modal>
  );
}

function NewAlertModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: (payload: Record<string, unknown>) => Promise<void>;
}) {
  const [source, setSource] = useState<string>("manual");
  const [severity, setSeverity] = useState<string>("medium");
  const [signature, setSignature] = useState("");
  const [sourceIp, setSourceIp] = useState("");
  const [destIp, setDestIp] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    if (!signature.trim()) return;
    setSubmitting(true);
    try {
      await onCreate({
        source,
        severity,
        signature,
        source_ip: sourceIp || null,
        dest_ip: destIp || null,
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal title="New Alert" onClose={onClose}>
      <FormField label="Source">
        <select value={source} onChange={(e) => setSource(e.target.value)} className={inputClass}>
          {ALERT_SOURCES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </FormField>
      <FormField label="Severity">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={inputClass}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </FormField>
      <FormField label="Signature">
        <input
          value={signature}
          onChange={(e) => setSignature(e.target.value)}
          className={inputClass}
          placeholder="e.g. Suspicious login pattern"
        />
      </FormField>
      <FormField label="Source IP (optional)">
        <input value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} className={inputClass} />
      </FormField>
      <FormField label="Dest IP (optional)">
        <input value={destIp} onChange={(e) => setDestIp(e.target.value)} className={inputClass} />
      </FormField>
      <button
        onClick={submit}
        disabled={submitting || !signature.trim()}
        className="border border-console-border rounded px-3 py-2 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
      >
        {submitting ? "Creating..." : "Create Alert"}
      </button>
    </Modal>
  );
}

function NewIncidentModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: (payload: Record<string, unknown>) => Promise<void>;
}) {
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<string>("medium");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    if (!title.trim()) return;
    setSubmitting(true);
    try {
      await onCreate({ title, severity, description: description || null, alert_ids: [] });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal title="New Incident" onClose={onClose}>
      <FormField label="Title">
        <input value={title} onChange={(e) => setTitle(e.target.value)} className={inputClass} />
      </FormField>
      <FormField label="Severity">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className={inputClass}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </FormField>
      <FormField label="Description (optional)">
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className={inputClass}
          rows={3}
        />
      </FormField>
      <button
        onClick={submit}
        disabled={submitting || !title.trim()}
        className="border border-console-border rounded px-3 py-2 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
      >
        {submitting ? "Creating..." : "Create Incident"}
      </button>
    </Modal>
  );
}

function NewConfigModal({
  onClose,
  onCreate,
}: {
  onClose: () => void;
  onCreate: (payload: Record<string, unknown>) => Promise<void>;
}) {
  const [name, setName] = useState("");
  const [ruleType, setRuleType] = useState<string>("correlation");
  const [threshold, setThreshold] = useState("");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    if (!name.trim()) return;
    setSubmitting(true);
    try {
      await onCreate({
        name,
        rule_type: ruleType,
        enabled: true,
        threshold: threshold ? Number(threshold) : null,
        description: description || null,
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal title="New Detection Config" onClose={onClose}>
      <FormField label="Name">
        <input value={name} onChange={(e) => setName(e.target.value)} className={inputClass} />
      </FormField>
      <FormField label="Rule Type">
        <select value={ruleType} onChange={(e) => setRuleType(e.target.value)} className={inputClass}>
          {RULE_TYPES.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </FormField>
      <FormField label="Threshold (optional)">
        <input
          type="number"
          value={threshold}
          onChange={(e) => setThreshold(e.target.value)}
          className={inputClass}
        />
      </FormField>
      <FormField label="Description (optional)">
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className={inputClass}
          rows={2}
        />
      </FormField>
      <button
        onClick={submit}
        disabled={submitting || !name.trim()}
        className="border border-console-border rounded px-3 py-2 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
      >
        {submitting ? "Creating..." : "Create Config"}
      </button>
    </Modal>
  );
}

function AIAnalysisPanel({
  available,
  model,
  availabilityError,
  loading,
  result,
  error,
  onAnalyze,
}: {
  available: boolean | null;
  model: string | null;
  availabilityError: string | null;
  loading: boolean;
  result: AIAnalysis | null;
  error: string | null;
  onAnalyze: () => void;
}) {
  return (
    <section className="border-t border-console-border pt-3 flex flex-col gap-2">
      <h3 className="text-xs uppercase tracking-wider text-console-accent">
        Gemini analyst assistant
      </h3>
      {available === false ? (
        <p className="text-xs text-console-dim">
          AI analysis is unavailable. An administrator can configure GEMINI_API_KEY on the
          backend and restart it. The SIEM remains fully operational without this option.
        </p>
      ) : (
        <>
          <p className="text-xs text-console-dim">
            {availabilityError ??
              (available === null
                ? "Checking Gemini availability..."
                : `Optional AI-assisted explanation using ${model ?? "Gemini"}.`)}
          </p>
          <button
            type="button"
            onClick={onAnalyze}
            disabled={available !== true || loading || availabilityError !== null}
            className="border border-console-border rounded px-3 py-1.5 text-xs uppercase tracking-wider hover:border-console-accent hover:text-console-accent transition-colors disabled:opacity-50"
          >
            {loading ? "Analyzing..." : "Analyze with Gemini"}
          </button>
        </>
      )}
      {loading && (
        <p role="status" className="text-xs text-console-dim">
          Requesting an AI-generated analysis...
        </p>
      )}
      {error && (
        <p role="alert" className="text-xs text-console-crit">
          {error}
        </p>
      )}
      {result && (
        <div className="flex flex-col gap-2 text-xs">
          <div>
            <h4 className="font-semibold text-console-text">Observed SIEM evidence</h4>
            <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded bg-console-bg p-2 text-console-dim">
              {JSON.stringify(result.observed_evidence, null, 2)}
            </pre>
          </div>
          <div>
            <h4 className="font-semibold text-console-text">
              AI-generated interpretation (unverified)
            </h4>
            <p className="mt-1 whitespace-pre-wrap break-words text-console-dim">
              {result.ai_interpretation}
            </p>
          </div>
          <p className="text-console-dim">{result.disclaimer}</p>
          <p className="text-console-dim">
            Model: {result.model} · Generated {new Date(result.generated_at).toLocaleString()}
          </p>
        </div>
      )}
    </section>
  );
}

function DetailPanel({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div className="w-80 shrink-0 border border-console-border rounded bg-console-panel p-4 flex flex-col gap-3 overflow-auto">
      <div className="flex items-center justify-between">
        <h2 className="text-xs uppercase tracking-widest text-console-accent">{title}</h2>
        <button onClick={onClose} className="text-console-dim hover:text-console-text">
          ×
        </button>
      </div>
      {children}
    </div>
  );
}

function EmptyState({ message }: { message: string }) {
  return <div className="p-10 text-center text-console-dim text-sm">{message}</div>;
}

function Th({ children }: { children?: ReactNode }) {
  return <th className="px-4 py-2 font-medium">{children}</th>;
}

function Td({
  children,
  className = "",
}: {
  children?: ReactNode;
  className?: string;
}) {
  return <td className={`px-4 py-2 ${className}`}>{children}</td>;
}
