import { createFileRoute } from "@tanstack/react-router";
import { useAuth, api } from "@/context/auth-context";
import { User, Shield, Gauge } from "lucide-react";
import { useState, useEffect } from "react";
import { Slider } from "@/components/ui/slider";
import { toast } from "sonner";

export const Route = createFileRoute("/settings")({
  component: SettingsPage,
});

function SettingsPage() {
  const { user } = useAuth();
  const [threshold, setThreshold] = useState<number>(0.80);
  const [isSaving, setIsSaving] = useState(false);

  useEffect(() => {
    if (user?.is_staff) {
      api.get("/sniffer/threshold/")
        .then((res) => {
          setThreshold(res.data.threshold);
        })
        .catch((err) => console.error("Failed to fetch detection threshold", err));
    }
  }, [user]);

  const handleThresholdChange = (val: number[]) => {
    setThreshold(val[0]);
  };

  const saveThreshold = () => {
    setIsSaving(true);
    api.post("/sniffer/threshold/", { threshold })
      .then((res) => {
        setThreshold(res.data.threshold);
        toast.success("Anomaly detection sensitivity updated successfully!");
      })
      .catch((err) => {
        console.error("Failed to update threshold", err);
        toast.error("Failed to update detection sensitivity");
      })
      .finally(() => setIsSaving(false));
  };
  
  return (
    <div className="mx-auto max-w-4xl">
      <div className="mb-8">
        <h1 className="text-2xl font-bold tracking-tight">Account Settings</h1>
        <p className="text-sm text-muted-foreground">
          View your profile details and configure engine sensitivity parameters.
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-6 h-fit">
          <div className="flex items-center gap-4 border-b border-border pb-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
              <User className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">{user?.username}</h2>
              <p className="text-sm text-muted-foreground">{user?.email}</p>
            </div>
          </div>
          <div className="pt-4">
            <div className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-muted-foreground" />
              <span className="font-medium">Role:</span>
              <span className="rounded-md bg-muted px-2 py-0.5 text-xs font-semibold uppercase">
                {user?.is_staff ? "Administrator" : "Analyst"}
              </span>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Your role defines what actions you can take within the IDS dashboard. Administrators have full system access.
            </p>
          </div>
        </div>

        {user?.is_staff && (
          <div className="rounded-lg border border-border bg-card p-6">
            <div className="flex items-center gap-3 border-b border-border pb-4 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Gauge className="h-5 w-5" />
              </div>
              <div>
                <h2 className="text-base font-semibold">IDS Detection Sensitivity</h2>
                <p className="text-xs text-muted-foreground">Adjust the threshold of the Tier 1 Anomaly Detector.</p>
              </div>
            </div>

            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium">Anomaly Threshold</span>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    Higher values reduce false positive alerts from normal background traffic.
                  </p>
                </div>
                <span className="text-lg font-bold text-primary font-mono">
                  {Math.round(threshold * 100)}%
                </span>
              </div>

              <div className="py-2">
                <Slider
                  value={[threshold]}
                  onValueChange={handleThresholdChange}
                  min={0.10}
                  max={0.95}
                  step={0.05}
                />
                <div className="flex justify-between text-[10px] text-muted-foreground mt-2 font-mono">
                  <span>10% (High Noise)</span>
                  <span>50% (Default)</span>
                  <span>80% (Recommended)</span>
                  <span>95% (Strict Anomaly)</span>
                </div>
              </div>

              <button
                onClick={saveThreshold}
                disabled={isSaving}
                className="inline-flex h-9 items-center justify-center rounded-md bg-primary px-4 py-2 text-xs font-semibold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-50"
              >
                {isSaving ? "Saving Settings..." : "Save Anomaly Settings"}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
