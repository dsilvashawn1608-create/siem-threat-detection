import { useEffect, useMemo, useState, useCallback } from "react";
import type { ReactNode } from "react";
import { StatusDot } from "./components/StatusDot";
import { ConsoleField } from "./components/ConsoleField";
import { Modal, FormField, inputClass } from "./components/Modal";

const API_BASE = "/api/v1";

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

type Tab = "alerts" | "incidents" | "ml" | "configs";

const SEVERITIES = ["low", "medium", "high", "critical"] as const;
const ALERT_SOURCES = ["snort", "splunk", "ml_anomaly", "manual"] as const;
const ALERT_STATUSES = ["new", "acknowledged", "escalated", "closed", "false_positive"] as const;
const INCIDENT_STATUSES = ["open", "investigating", "contained", "resolved", "closed"] as const;
const RULE_TYPES = ["snort_rule", "ml_threshold", "splunk_search", "correlation"] as const;

async function fetchJSON<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`${resp.status} ${resp.statusText}: ${text}`);
  }
  return resp.json();
}

export default function App() {
  const [tab, setTab] = useState<Tab>("alerts");
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [models, setModels] = useState<MLModel[]>([]);
  const [configs, setConfigs] = useState<DetectionConfig[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [actionMessage, setActionMessage] = useState<string | null>(null);

  const [showNewAlert, setShowNewAlert] = useState(false);
  const [showNewIncident, setShowNewIncident] = useState(false);
  const [showNewConfig, setShowNewConfig] = useState(false);

  // --- Alert filters ---
  const [alertSource, setAlertSource] = useState<string>("");
  const [alertSeverity, setAlertSeverity] = useState<string>("");
  const [alertStatus, setAlertStatus] = useState<string>("");
  const [alertSearch, setAlertSearch] = useState<string>("");

  // --- Incident filters ---
  const [incidentSeverity, setIncidentSeverity] = useState<string>("");
  const [incidentStatus, setIncidentStatus] = useState<string>("");

  const refresh = useCallback(async () => {
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
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 15000);
    return () => clearInterval(interval);
  }, [refresh]);

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
      fetchJSON(`/alerts/${alert.id}?actor=analyst-ui`, {
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
      fetchJSON(`/incidents/${incident.id}?actor=analyst-ui`, {
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
            {lastRefreshed ? `last sync ${lastRefreshed.toLocaleTimeString()}` : "syncing..."}
          </span>
          <button
            onClick={() => refresh()}
            className="border border-console-border rounded px-3 py-1 hover:border-console-accent hover:text-console-accent transition-colors"
          >
            {loading ? "REFRESHING" : "REFRESH"}
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
            <SmallButton onClick={() => setShowNewAlert(true)}>+ New Alert</SmallButton>
          )}
          {tab === "incidents" && (
            <>
              <SmallButton onClick={runCorrelation}>Run Correlation</SmallButton>
              <SmallButton onClick={() => setShowNewIncident(true)}>+ New Incident</SmallButton>
            </>
          )}
          {tab === "configs" && (
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
          {tab === "ml" && <MLPanel models={models} onTrain={refresh} />}
          {tab === "configs" && <ConfigsPanel configs={configs} onToggle={toggleConfig} />}
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

function MLPanel({ models, onTrain }: { models: MLModel[]; onTrain: () => Promise<void> }) {
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
}: {
  configs: DetectionConfig[];
  onToggle: (c: DetectionConfig) => void;
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
            </Td>
          </tr>
        ))}
      </tbody>
    </table>
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
