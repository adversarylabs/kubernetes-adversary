import { Adversary, Severity, type ObservationInit } from "@adversarylabs/sdk";
import { type RuleSpec } from "./spec.js";
export declare function registerRules(app: Adversary): void;
export declare function observationFor(detection: {
    rule: RuleSpec;
    file: string;
    line: number;
    snippet: string;
    label: string;
    data: Record<string, unknown>;
}): ObservationInit;
export { Severity };
