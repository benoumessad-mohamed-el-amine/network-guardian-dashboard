import * as React from "react";
import { useAuth } from "@/context/auth-context";
import { Shield, Loader2, AlertCircle, UserPlus, Eye, EyeOff } from "lucide-react";
import { motion } from "framer-motion";
import { api } from "@/context/auth-context";
import logoUrl from "@/assets/logo.png";
import { ThemeToggle } from "@/components/theme-toggle";

export function LoginPage() {
  const [username, setUsername] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [showPassword, setShowPassword] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [successMessage, setSuccessMessage] = React.useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = React.useState(false);
  const { login, needsSetup } = useAuth();

  // Wizard state: "login" | "forgot" | "reset"
  const [mode, setMode] = React.useState<"login" | "forgot" | "reset">("login");
  const [identity, setIdentity] = React.useState("");
  const [otp, setOtp] = React.useState("");
  const [newPassword, setNewPassword] = React.useState("");
  const [showNewPassword, setShowNewPassword] = React.useState(false);

  React.useEffect(() => {
    if (needsSetup) {
      document.title = "Initial System Setup — Soficlef Sentinel Flow";
    } else if (mode === "forgot") {
      document.title = "Reset Password — Soficlef Sentinel Flow";
    } else if (mode === "reset") {
      document.title = "Verify Code — Soficlef Sentinel Flow";
    } else {
      document.title = "Login — Soficlef Sentinel Flow";
    }
  }, [needsSetup, mode]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);
    setIsSubmitting(true);
    try {
      if (needsSetup) {
        // Register first user
        await api.post("/auth/register/", { username, password, email: `${username}@soficlef.local` });
        await login(username, password);
      } else {
        await login(username, password);
      }
    } catch (err: any) {
      setError(err.response?.data?.error || err.response?.data?.username?.[0] || "Authentication failed");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);
    setIsSubmitting(true);
    try {
      const res = await api.post("/auth/forgot-password/", { identity });
      setSuccessMessage(res.data.message || "OTP code sent to your email!");
      setMode("reset");
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to request password reset code");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);
    setIsSubmitting(true);
    try {
      const res = await api.post("/auth/reset-password/", { identity, otp, new_password: newPassword });
      setSuccessMessage(res.data.message || "Password reset successfully! You can now log in.");
      setMode("login");
      if (!identity.includes("@")) {
        setUsername(identity);
      }
      setPassword("");
    } catch (err: any) {
      setError(err.response?.data?.error || "Failed to reset password. Please verify the code.");
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background px-4 text-foreground transition-colors duration-300">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md"
      >
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-12 items-center justify-center">
            <img src={logoUrl} alt="Soficlef" className="h-8 w-auto object-contain" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            {needsSetup 
              ? "Initial System Setup" 
              : mode === "forgot"
              ? "Reset Password"
              : mode === "reset"
              ? "Verification Required"
              : "Sentinel Flow IDS"}
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            {needsSetup 
              ? "Create the master administrator account to initialize the system." 
              : mode === "forgot"
              ? "Enter your account username or email to receive a recovery code."
              : mode === "reset"
              ? "Enter the 6-digit OTP code sent to your registered email address."
              : "Enter your credentials to access the security console"}
          </p>
        </div>

        <div className="rounded-2xl border border-border bg-card/45 p-8 backdrop-blur-md shadow-lg">
          {error && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="mb-6 flex items-center gap-2 rounded-lg bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive"
            >
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span className="text-xs font-medium leading-normal">{error}</span>
            </motion.div>
          )}

          {successMessage && (
            <motion.div
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="mb-6 flex items-center gap-2 rounded-lg bg-success/10 border border-success/20 p-3 text-sm text-success"
            >
              <Shield className="h-4 w-4 text-success shrink-0" />
              <span className="text-xs font-medium leading-normal">{successMessage}</span>
            </motion.div>
          )}

          {mode === "login" && (
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  className="w-full rounded-xl border border-border bg-muted/20 px-4 py-3 text-sm text-foreground placeholder-muted-foreground/60 transition-all focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                  placeholder="admin"
                />
              </div>

              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    Password
                  </label>
                  {!needsSetup && (
                    <button
                      type="button"
                      onClick={() => {
                        setMode("forgot");
                        setError(null);
                        setSuccessMessage(null);
                      }}
                      className="text-xs font-semibold text-primary hover:underline transition-all"
                    >
                      Forgot Password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <input
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    className="w-full rounded-xl border border-border bg-muted/20 pl-4 pr-12 py-3 text-sm text-foreground placeholder-muted-foreground/60 transition-all focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {showPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="relative w-full overflow-hidden rounded-xl bg-primary px-4 py-3 text-sm font-bold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-50"
              >
                <span className="flex items-center justify-center gap-2">
                  {isSubmitting ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      {needsSetup ? "Creating Account..." : "Authenticating..."}
                    </>
                  ) : (
                    needsSetup ? "Initialize System" : "Access Dashboard"
                  )}
                </span>
              </button>
            </form>
          )}

          {mode === "forgot" && (
            <form onSubmit={handleForgotPassword} className="space-y-6">
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Username or Email
                </label>
                <input
                  type="text"
                  value={identity}
                  onChange={(e) => setIdentity(e.target.value)}
                  required
                  className="w-full rounded-xl border border-border bg-muted/20 px-4 py-3 text-sm text-foreground placeholder-muted-foreground/60 transition-all focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                  placeholder="Enter your username or email"
                />
              </div>

              <div className="flex flex-col gap-3">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="relative w-full overflow-hidden rounded-xl bg-primary px-4 py-3 text-sm font-bold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-50"
                >
                  <span className="flex items-center justify-center gap-2">
                    {isSubmitting ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Sending Code...
                      </>
                    ) : (
                      "Send Verification Code"
                    )}
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setMode("login");
                    setError(null);
                    setSuccessMessage(null);
                  }}
                  className="text-xs font-semibold text-muted-foreground hover:text-foreground text-center py-2"
                >
                  Back to Login
                </button>
              </div>
            </form>
          )}

          {mode === "reset" && (
            <form onSubmit={handleResetPassword} className="space-y-6">
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  Verification Code (OTP)
                </label>
                <input
                  type="text"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  required
                  maxLength={6}
                  className="w-full rounded-xl border border-border bg-muted/20 px-4 py-3 text-sm text-foreground font-mono text-center tracking-widest placeholder-muted-foreground/60 transition-all focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                  placeholder="123456"
                />
              </div>

              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                  New Password
                </label>
                <div className="relative">
                  <input
                    type={showNewPassword ? "text" : "password"}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    className="w-full rounded-xl border border-border bg-muted/20 pl-4 pr-12 py-3 text-sm text-foreground placeholder-muted-foreground/60 transition-all focus:border-primary/50 focus:outline-none focus:ring-1 focus:ring-primary/50"
                    placeholder="••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {showNewPassword ? (
                      <EyeOff className="h-4 w-4" />
                    ) : (
                      <Eye className="h-4 w-4" />
                    )}
                  </button>
                </div>
              </div>

              <div className="flex flex-col gap-3">
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="relative w-full overflow-hidden rounded-xl bg-primary px-4 py-3 text-sm font-bold text-primary-foreground transition-all hover:bg-primary/90 disabled:opacity-50"
                >
                  <span className="flex items-center justify-center gap-2">
                    {isSubmitting ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" />
                        Resetting Password...
                      </>
                    ) : (
                      "Reset Password"
                    )}
                  </span>
                </button>
                <div className="flex justify-between px-1">
                  <button
                    type="button"
                    onClick={(e) => handleForgotPassword(e)}
                    className="text-xs font-semibold text-primary hover:underline"
                  >
                    Resend Code
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setMode("login");
                      setError(null);
                      setSuccessMessage(null);
                    }}
                    className="text-xs font-semibold text-muted-foreground hover:text-foreground"
                  >
                    Back to Login
                  </button>
                </div>
              </div>
            </form>
          )}
        </div>

        <p className="mt-8 text-center text-xs text-muted-foreground">
          &copy; 2026 Soficlef Sentinel Security Systems. All rights reserved.
        </p>
      </motion.div>
    </div>
  );
}
