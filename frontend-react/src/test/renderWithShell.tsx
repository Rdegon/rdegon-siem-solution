import { render, type RenderOptions } from "@testing-library/react";
import type { ReactElement, ReactNode } from "react";
import { ShellContext } from "../shell/context";
import { FeedbackProvider } from "../shell/feedback";

type ShellRenderOptions = RenderOptions & {
  lang?: "en" | "ru";
  timezone?: string;
};

export function renderWithShell(ui: ReactElement, options: ShellRenderOptions = {}) {
  const {
    lang = "en",
    timezone = "Europe/Moscow",
    ...renderOptions
  } = options;

  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <ShellContext.Provider
        value={{
          lang,
          setLang: () => undefined,
          theme: "dark",
          timezone,
          setTimezone: () => undefined,
          permissions: [],
          sectionAccess: [],
          formatTimestamp: () => "n/a",
          toInputDateTime: () => "",
          toUtcQueryValue: () => "",
        }}
      >
        <FeedbackProvider>{children}</FeedbackProvider>
      </ShellContext.Provider>
    );
  }

  return render(ui, {
    wrapper: Wrapper,
    ...renderOptions,
  });
}
