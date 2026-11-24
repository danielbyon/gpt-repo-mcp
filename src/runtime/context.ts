import { RootRegistry } from "../services/root-registry.js";
import type { CodeIntelligenceService } from "../services/code-intelligence-service.js";

export type RuntimeContext = Readonly<{
  registry: RootRegistry;
  codeIntelligence?: CodeIntelligenceService;
}>;
