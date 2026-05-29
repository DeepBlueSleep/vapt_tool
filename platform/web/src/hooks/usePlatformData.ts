import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../api";
import type { CreateScanRequest, Metrics, Scan } from "../types";

export function usePlatformData() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const selected = useMemo(() => scans.find((scan) => scan.id === selectedId) ?? scans[0] ?? null, [scans, selectedId]);

  const refresh = useCallback(async () => {
    try {
      setError(null);
      const [scanList, metricSummary] = await Promise.all([api.scans(), api.metrics()]);
      setScans(scanList);
      setMetrics(metricSummary);
      setSelectedId((current) => {
        if (current && scanList.some((scan) => scan.id === current)) return current;
        return scanList[0]?.id ?? null;
      });
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to load platform data.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 6000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  async function createScan(payload: CreateScanRequest) {
    setLoading(true);
    try {
      const created = await api.createScan(payload);
      setSelectedId(created.id);
      await refresh();
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "Unable to create scan.");
    } finally {
      setLoading(false);
    }
  }

  async function deleteScan(scanId: number) {
    if (!window.confirm("Delete this scan and its generated report metadata?")) return;
    await api.deleteScan(scanId);
    setSelectedId((current) => (current === scanId ? null : current));
    await refresh();
  }

  async function deleteAllScans() {
    if (!window.confirm("Delete all scans and report metadata from this workspace?")) return;
    await api.deleteAllScans();
    setSelectedId(null);
    await refresh();
  }

  return {
    scans,
    metrics,
    selected,
    selectedId,
    loading,
    error,
    setSelectedId,
    refresh,
    createScan,
    deleteScan,
    deleteAllScans
  };
}
