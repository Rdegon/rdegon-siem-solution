import type { Preview } from "@storybook/react";
import { MemoryRouter } from "react-router-dom";
import "../src/styles.css";
import { ShellContext } from "../src/shell/context";
import { FeedbackProvider } from "../src/shell/feedback";

const preview: Preview = {
  parameters: {
    layout: "fullscreen",
    backgrounds: {
      default: "sentinel",
      values: [{ name: "sentinel", value: "#040a12" }],
    },
    controls: { expanded: true },
  },
  decorators: [
    (Story) => (
      <MemoryRouter>
        <ShellContext.Provider
          value={{
            lang: "en",
            setLang: () => undefined,
            theme: "dark",
            timezone: "Europe/Moscow",
            setTimezone: () => undefined,
            formatTimestamp: (value: unknown) => String(value || "n/a"),
            toInputDateTime: () => "",
            toUtcQueryValue: () => "",
          }}
        >
          <FeedbackProvider>
            <div style={{ minHeight: "100vh", padding: 24 }}>
              <Story />
            </div>
          </FeedbackProvider>
        </ShellContext.Provider>
      </MemoryRouter>
    ),
  ],
};

export default preview;

