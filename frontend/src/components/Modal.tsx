import type { ReactNode } from "react";

export function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  return (
    <div
      className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="bg-console-panel border border-console-border rounded w-full max-w-md p-5 flex flex-col gap-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-xs uppercase tracking-widest text-console-accent">{title}</h2>
          <button onClick={onClose} className="text-console-dim hover:text-console-text">
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

export function FormField({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[10px] uppercase tracking-widest text-console-dim">{label}</span>
      {children}
    </label>
  );
}

export const inputClass =
  "bg-console-bg border border-console-border rounded px-3 py-1.5 text-sm text-console-text focus:outline-none focus:border-console-accent";
