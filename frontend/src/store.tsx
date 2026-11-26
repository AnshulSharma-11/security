import { createContext, useContext } from "react";
export type Ctx = { user: any; projects: any[]; project: any | null; setProject: (p: any) => void; logout: () => void };
export const AppCtx = createContext<Ctx>(null as any);
export const useApp = () => useContext(AppCtx);
