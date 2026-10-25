import { useEffect, useState } from 'react';
import { Shield } from 'lucide-react';

const STEPS = ['ESTABLISHING SECURE CHANNEL', 'VERIFYING SESSION TOKEN', 'SYNCING TELEMETRY'];

export default function BootScreen() {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => setStep((s) => (s + 1) % STEPS.length), 700);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="boot" role="status" aria-live="polite">
      <div className="boot-core">
        <div className="boot-rings"><span /><span /><span /><Shield size={34} /></div>
        <div className="boot-text">{STEPS[step]}…</div>
        <div className="boot-bar"><i /></div>
      </div>
    </div>
  );
}
