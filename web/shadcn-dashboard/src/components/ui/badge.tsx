import type React from "react"
import { cn } from "../../utils/cn"

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: "default" | "secondary" | "destructive" | "outline" | "critical" | "high" | "medium" | "low"
}

function Badge({ className, variant = "default", ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold transition-colors",
        {
          "bg-primary text-primary-foreground": variant === "default",
          "bg-secondary text-secondary-foreground": variant === "secondary",
          "bg-destructive text-destructive-foreground": variant === "destructive",
          "border border-input bg-background": variant === "outline",
          "bg-red-500/20 text-red-400": variant === "critical",
          "bg-orange-500/20 text-orange-400": variant === "high",
          "bg-yellow-500/20 text-yellow-400": variant === "medium",
          "bg-green-500/20 text-green-400": variant === "low",
        },
        className
      )}
      {...props}
    />
  )
}

export { Badge }
