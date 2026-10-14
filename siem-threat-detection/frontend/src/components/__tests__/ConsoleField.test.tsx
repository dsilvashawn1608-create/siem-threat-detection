import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { ConsoleField } from "../ConsoleField";

describe("ConsoleField", () => {
  it("renders the label and a string value", () => {
    render(<ConsoleField label="Source IP" value="10.0.0.5" />);
    expect(screen.getByText("Source IP")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
  });

  it("renders a React node as the value", () => {
    render(<ConsoleField label="Severity" value={<strong>critical</strong>} />);
    const strong = screen.getByText("critical");
    expect(strong.tagName).toBe("STRONG");
  });
});
