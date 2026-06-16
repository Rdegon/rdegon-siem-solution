import type { ReactNode } from "react";
import { EmptyState } from "./chrome";
import type { DataState } from "./hooks";

export function AsyncGate({
  states,
  loadingMessage,
  children,
}: {
  states: Array<DataState<unknown>>;
  loadingMessage: string;
  children: ReactNode;
}) {
  const hasResolvedData = states.some((state) => state.data !== null);
  const blockingError = states.find((state) => Boolean(state.error) && state.data === null);

  if (!hasResolvedData && states.some((state) => state.loading)) {
    return <EmptyState message={loadingMessage} />;
  }
  if (blockingError) {
    return <EmptyState message={blockingError.error} />;
  }
  return <>{children}</>;
}
