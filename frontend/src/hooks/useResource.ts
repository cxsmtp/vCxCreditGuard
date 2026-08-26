import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError } from "../api/client";

interface ResourceState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  /** True only for the first load. Refetches keep the previous render visible
   * rather than flashing a skeleton, which would jump the layout. */
  initialLoading: boolean;
}

export interface Resource<T> extends ResourceState<T> {
  reload: () => Promise<void>;
  setData: (data: T) => void;
}

/**
 * Minimal data fetching hook. Deliberately not a caching library: every page here
 * shows live governance state, where a stale cache would be actively misleading.
 */
export function useResource<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  dependencies: unknown[] = [],
): Resource<T> {
  const [state, setState] = useState<ResourceState<T>>({
    data: null,
    error: null,
    loading: true,
    initialLoading: true,
  });
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(async (signal: AbortSignal) => {
    setState((current) => ({ ...current, loading: true, error: null }));
    try {
      const data = await loaderRef.current(signal);
      if (!mounted.current || signal.aborted) return;
      setState({ data, error: null, loading: false, initialLoading: false });
    } catch (error) {
      if (!mounted.current || signal.aborted) return;
      if (error instanceof DOMException && error.name === "AbortError") return;
      const message =
        error instanceof ApiError ? error.message : "Something went wrong loading this page.";
      setState((current) => ({
        data: current.data,
        error: message,
        loading: false,
        initialLoading: false,
      }));
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    void run(controller.signal);
    return () => controller.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, dependencies);

  const reload = useCallback(async () => {
    const controller = new AbortController();
    await run(controller.signal);
  }, [run]);

  const setData = useCallback((data: T) => {
    setState((current) => ({ ...current, data }));
  }, []);

  return { ...state, reload, setData };
}

/** Polls while the tab is visible. Used by the dashboard and notification badge. */
export function useInterval(callback: () => void, delayMs: number | null): void {
  const callbackRef = useRef(callback);
  callbackRef.current = callback;

  useEffect(() => {
    if (delayMs === null) return;
    const id = window.setInterval(() => {
      if (document.visibilityState === "visible") callbackRef.current();
    }, delayMs);
    return () => window.clearInterval(id);
  }, [delayMs]);
}
