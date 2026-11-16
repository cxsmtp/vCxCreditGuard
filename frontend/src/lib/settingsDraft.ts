import { useEffect, useSyncExternalStore } from "react";

/*
  Unsaved settings, kept outside any one page.

  Settings are split over several pages that sit one click apart, but are saved
  together. The draft lives here so moving between those pages does not drop
  what was typed, the unsaved-changes bar follows the person to every settings
  page, and the browser asks before the tab is closed or reloaded.
*/

export interface DraftState<T> {
  draft: T;
  removeWebhook: boolean;
}

let state: DraftState<Record<string, unknown>> = { draft: {}, removeWebhook: false };
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

export const settingsDraft = {
  get: () => state,
  subscribe(listener: () => void) {
    listeners.add(listener);
    return () => listeners.delete(listener);
  },
  patch(changes: Record<string, unknown>) {
    state = { ...state, draft: { ...state.draft, ...changes } };
    emit();
  },
  setRemoveWebhook(value: boolean) {
    state = { ...state, removeWebhook: value };
    emit();
  },
  clear() {
    state = { draft: {}, removeWebhook: false };
    emit();
  },
  dirty(): boolean {
    return (
      state.removeWebhook || Object.values(state.draft).some((value) => value !== undefined)
    );
  },
};

export function useSettingsDraft<T>(): DraftState<T> {
  return useSyncExternalStore(settingsDraft.subscribe, settingsDraft.get) as DraftState<T>;
}

/** While there are unsaved settings, closing or reloading the tab asks first. */
export function useWarnBeforeUnload(active: boolean) {
  useEffect(() => {
    if (!active) return;
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [active]);
}
