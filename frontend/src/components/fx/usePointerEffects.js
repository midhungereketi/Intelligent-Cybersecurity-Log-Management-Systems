import { useEffect } from 'react';

/**
 * Global pointer effects, wired once at the app root:
 * - `.card` / `.stat-card` / `.feed-item` receive --mx/--my for the hover spotlight
 * - `.stat-card` tilts in 3D toward the pointer
 * - `.cursor-glow` follows the pointer
 */
export default function usePointerEffects() {
  useEffect(() => {
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return undefined;
    let tilted = null;
    let frame = 0;
    let last = null;

    const resetTilt = () => {
      if (tilted) {
        tilted.style.setProperty('--rx', '0deg');
        tilted.style.setProperty('--ry', '0deg');
        tilted = null;
      }
    };

    const apply = () => {
      frame = 0;
      const event = last;
      if (!event) return;
      const glow = document.querySelector('.cursor-glow');
      if (glow) {
        glow.style.setProperty('--cx', `${event.clientX}px`);
        glow.style.setProperty('--cy', `${event.clientY}px`);
      }
      const target = event.target instanceof Element ? event.target : null;
      const surface = target?.closest('.card, .stat-card, .feed-item');
      if (surface) {
        const rect = surface.getBoundingClientRect();
        surface.style.setProperty('--mx', `${event.clientX - rect.left}px`);
        surface.style.setProperty('--my', `${event.clientY - rect.top}px`);
      }
      const card = target?.closest('.stat-card');
      if (card !== tilted) resetTilt();
      if (card) {
        const rect = card.getBoundingClientRect();
        const px = (event.clientX - rect.left) / rect.width - 0.5;
        const py = (event.clientY - rect.top) / rect.height - 0.5;
        card.style.setProperty('--rx', `${(-py * 8).toFixed(2)}deg`);
        card.style.setProperty('--ry', `${(px * 10).toFixed(2)}deg`);
        tilted = card;
      }
    };

    const onMove = (event) => {
      last = event;
      if (!frame) frame = requestAnimationFrame(apply);
    };

    window.addEventListener('pointermove', onMove, { passive: true });
    document.addEventListener('pointerleave', resetTilt);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('pointermove', onMove);
      document.removeEventListener('pointerleave', resetTilt);
    };
  }, []);
}
