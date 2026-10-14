import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { Modal, FormField } from "../Modal";

describe("Modal", () => {
  it("renders its title and children", () => {
    render(
      <Modal title="New Alert" onClose={() => {}}>
        <div>form contents</div>
      </Modal>
    );
    expect(screen.getByText("New Alert")).toBeInTheDocument();
    expect(screen.getByText("form contents")).toBeInTheDocument();
  });

  it("calls onClose when the backdrop is clicked", () => {
    const onClose = vi.fn();
    render(
      <Modal title="New Alert" onClose={onClose}>
        <div>contents</div>
      </Modal>
    );
    // The outermost fixed-position overlay is the backdrop.
    const backdrop = screen.getByText("contents").closest(".fixed");
    fireEvent.click(backdrop!);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does not call onClose when clicking inside the dialog", () => {
    const onClose = vi.fn();
    render(
      <Modal title="New Alert" onClose={onClose}>
        <div>contents</div>
      </Modal>
    );
    fireEvent.click(screen.getByText("contents"));
    expect(onClose).not.toHaveBeenCalled();
  });

  it("calls onClose when the × button is clicked", () => {
    const onClose = vi.fn();
    render(
      <Modal title="New Alert" onClose={onClose}>
        <div>contents</div>
      </Modal>
    );
    fireEvent.click(screen.getByText("×"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("FormField", () => {
  it("renders a label wrapping its children", () => {
    render(
      <FormField label="Signature">
        <input defaultValue="test" />
      </FormField>
    );
    expect(screen.getByText("Signature")).toBeInTheDocument();
    expect(screen.getByDisplayValue("test")).toBeInTheDocument();
  });
});
