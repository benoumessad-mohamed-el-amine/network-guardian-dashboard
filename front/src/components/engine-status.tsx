import { Play, Square } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useMonitoring } from "@/context/monitoring-context";
import { cn } from "@/lib/utils";
import { useState, useEffect } from "react";
import { useAuth, api } from "@/context/auth-context";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";

export function EngineStatus() {
  const { running, activeInterface, toggle } = useMonitoring();
  const { user } = useAuth();
  const [selectedInterface, setSelectedInterface] = useState("any");
  const [customInterface, setCustomInterface] = useState("");
  const [interfaces, setInterfaces] = useState<{ name: string; description: string; ip: string }[]>([]);

  useEffect(() => {
    if (user?.is_staff) {
      api.get("/sniffer/interfaces/")
        .then((res) => {
          setInterfaces(res.data);
        })
        .catch((err) => console.error("Failed to fetch interfaces", err));
    }
  }, [user]);

  const handleToggle = () => {
    if (running) {
      toggle();
    } else {
      const iface = selectedInterface === "custom" ? customInterface : selectedInterface;
      toggle(iface || "any");
    }
  };

  return (
    <div className="flex items-center gap-3">
      {/* Interface selection when idle */}
      {!running && user?.is_staff && (
        <div className="flex items-center gap-2">
          <Select value={selectedInterface} onValueChange={setSelectedInterface}>
            <SelectTrigger className="w-[180px] h-9 bg-card border-border text-xs">
              <SelectValue placeholder="Select Interface" />
            </SelectTrigger>
            <SelectContent className="bg-card border-border text-xs max-h-[300px] overflow-y-auto">
              <SelectItem value="any">Auto (Any Interface)</SelectItem>
              {interfaces.map((iface) => (
                <SelectItem key={iface.name} value={iface.name}>
                  {iface.name} {iface.ip ? `(${iface.ip})` : ""} - {iface.description}
                </SelectItem>
              ))}
              <SelectItem value="custom">Custom Interface...</SelectItem>
            </SelectContent>
          </Select>

          {selectedInterface === "custom" && (
            <Input
              placeholder="e.g. wlan1"
              value={customInterface}
              onChange={(e) => setCustomInterface(e.target.value)}
              className="w-[100px] h-9 text-xs bg-card border-border"
            />
          )}
        </div>
      )}

      {/* Engine status indicator */}
      <div className="flex items-center gap-2 rounded-md border border-border bg-card/50 px-3 py-1.5">
        <span className="relative flex h-2 w-2">
          {running && (
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success/60 opacity-75" />
          )}
          <span
            className={cn(
              "relative inline-flex h-2 w-2 rounded-full",
              running ? "bg-success" : "bg-muted-foreground",
            )}
          />
        </span>
        <span className="text-xs font-medium tracking-wide text-muted-foreground">
          Engine
        </span>
        <span className="text-xs font-semibold">
          {running ? `Monitoring (${activeInterface || "any"})` : "Idle"}
        </span>
      </div>

      {user?.is_staff && (
        <Button
          size="sm"
          variant={running ? "destructive" : "default"}
          onClick={handleToggle}
          className="gap-2"
        >
          {running ? <Square className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
          {running ? "Stop Monitoring" : "Start Monitoring"}
        </Button>
      )}
    </div>
  );
}
