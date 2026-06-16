import { fireEvent, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useFeedback, FeedbackProvider } from "../feedback";
import { renderWithShell } from "../../test/renderWithShell";

function FeedbackHarness() {
  const { pushToast } = useFeedback();
  return (
    <button
      type="button"
      onClick={() =>
        pushToast({
          title: "Saved",
          message: "Connector definition stored",
          tone: "success",
        })
      }
    >
      Trigger toast
    </button>
  );
}

describe("FeedbackProvider", () => {
  it("renders toast notifications and exposes a dismiss action", async () => {
    renderWithShell(
      <FeedbackProvider>
        <FeedbackHarness />
      </FeedbackProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "Trigger toast" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Connector definition stored");
    fireEvent.click(screen.getByRole("button", { name: "Dismiss notification" }));
    expect(screen.queryByText("Connector definition stored")).not.toBeInTheDocument();
  });
});
