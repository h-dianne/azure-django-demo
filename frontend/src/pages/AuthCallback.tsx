import { useEffect } from "react";
import { handleCallback } from "../auth/oidc";
import { useNavigate } from "react-router-dom";

export default function AuthCallback() {
  const nav = useNavigate();
  useEffect(() => {
    handleCallback().finally(() => nav("/"));
  }, [nav]);
  return <p className="p-6">Signing you in…</p>;
}
