/**
 * PWA frontend resource governor. Listens for SWARM_DENSITY_SHIFT events from
 * the native webview bridge and throttles the interface (animation loops,
 * telemetry polling) when the Rust core parks cohorts under thermal/memory
 * pressure. Zero dependencies.
 */

export interface TelemetryPacket {
  cpuThermalCelsius: number;
  batteryDepletionDerivative: number;
  hardwareMemoryPressurePct: number;
  activeSwarmCount: number;
}

export class DynamicResourceOptimizer {
  private isThrottledState = false;
  private animationFrameId: number | null = null;
  private pollTimer: number | null = null;

  constructor() {
    window.addEventListener("message", (event: MessageEvent) => {
      if (event.data && event.data.type === "SWARM_DENSITY_SHIFT") {
        this.regulateFrontendExecutionFootprint(event.data.payload as TelemetryPacket);
      }
    });
  }

  private regulateFrontendExecutionFootprint(metrics: TelemetryPacket): void {
    const shouldThrottle =
      metrics.activeSwarmCount <= 5 || metrics.hardwareMemoryPressurePct > 85;

    if (shouldThrottle && !this.isThrottledState) {
      this.isThrottledState = true;
      if (this.animationFrameId !== null) {
        cancelAnimationFrame(this.animationFrameId);
        this.animationFrameId = null;
      }
      // Drop telemetry polling to 1/10 Hz while throttled.
      if (this.pollTimer !== null) {
        window.clearInterval(this.pollTimer);
      }
      this.pollTimer = window.setInterval(() => this.lightweightPoll(), 10_000);
    } else if (!shouldThrottle && this.isThrottledState) {
      this.isThrottledState = false;
      if (this.pollTimer !== null) {
        window.clearInterval(this.pollTimer);
        this.pollTimer = null;
      }
      this.resumeHighFidelityInterfaceLoops();
    }
  }

  private lightweightPoll(): void {
    // Minimal heartbeat while throttled; no rendering work.
    window.postMessage({ type: "PWA_HEARTBEAT", at: Date.now() }, "*");
  }

  private resumeHighFidelityInterfaceLoops(): void {
    const loop = () => {
      this.animationFrameId = requestAnimationFrame(loop);
    };
    this.animationFrameId = requestAnimationFrame(loop);
  }

  public get throttled(): boolean {
    return this.isThrottledState;
  }
}
