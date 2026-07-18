/**
 * @brick-auth/react — Plug-and-play BRICK authentication SDK
 *
 * Usage:
 *   import { BrickAuthProvider, useBrickAuth, SignIn, SignUp, OrganizationSwitcher } from "@/components/brick-auth";
 */

// Core provider + hook
export { BrickAuthProvider, useBrickAuth } from "./BrickAuthProvider";
export type {
  BrickUser,
  FabricIdentity,
  BrickSession,
  BrickAuthContextType,
} from "./BrickAuthProvider";

// UI Components
export { SignIn } from "./SignIn";
export { SignUp } from "./SignUp";
export { OrganizationSwitcher } from "./OrganizationSwitcher";
