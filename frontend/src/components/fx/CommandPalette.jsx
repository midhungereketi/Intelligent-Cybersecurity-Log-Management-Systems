import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { CornerDownLeft, LogOut, Search } from 'lucide-react';

/**
 * Ctrl/Cmd+K palette for jumping between workspace sections.
 * `items` are { id, label, icon, hint }; choosing one calls onSelect(id).
 */
export default function CommandPalette({ open, onClose, items, onSelect, onLogout }) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef(null);

  const actions = useMemo(() => {
    const nav = items.map((item) => ({ ...item, group: 'NAVIGATE', run: () => onSelect(item.id) }));
    const extra = [{ id: 'logout', label: 'Sign out', icon: LogOut, hint: 'Session', group: 'ACCOUNT', run: onLogout }];
    const q = query.trim().toLowerCase();
    return [...nav, ...extra].filter((a) => !q || a.label.toLowerCase().includes(q) || a.id.includes(q));
  }, [items, onSelect, onLogout, query]);

  useLayoutEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  if (!open) return null;

  const close = () => {
    setQuery('');
    setActive(0);
    onClose();
  };

  const choose = (action) => {
    close();
    action?.run();
  };

  const onKeyDown = (event) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActive((i) => (i + 1) % Math.max(actions.length, 1));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActive((i) => (i - 1 + actions.length) % Math.max(actions.length, 1));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      choose(actions[active]);
    } else if (event.key === 'Escape') {
      close();
    }
  };

  let lastGroup = null;
  return (
    <div className="cmdk-overlay" onMouseDown={close} role="presentation">
      <div className="cmdk" role="dialog" aria-modal="true" aria-label="Command palette" onMouseDown={(e) => e.stopPropagation()}>
        <div className="cmdk-input">
          <Search size={18} />
          <input ref={inputRef} value={query} placeholder="Jump to a section or run an action…"
            onChange={(e) => { setQuery(e.target.value); setActive(0); }} onKeyDown={onKeyDown} aria-label="Search commands" />
          <span className="kbd">ESC</span>
        </div>
        <div className="cmdk-list" role="listbox">
          {actions.length === 0 && <div className="empty-state">No matching commands.</div>}
          {actions.map((action, index) => {
            const Icon = action.icon;
            const header = action.group !== lastGroup ? <div className="cmdk-group">{action.group}</div> : null;
            lastGroup = action.group;
            return (
              <div key={action.id}>
                {header}
                <button type="button" role="option" aria-selected={index === active}
                  className={`cmdk-item ${index === active ? 'active' : ''}`}
                  onMouseEnter={() => setActive(index)} onClick={() => choose(action)}>
                  <span className="cmdk-icon">{Icon && <Icon size={16} />}</span>
                  <span>{action.label}</span>
                  <small>{action.hint}</small>
                </button>
              </div>
            );
          })}
        </div>
        <div className="cmdk-foot">
          <span><span className="kbd">↑↓</span> navigate</span>
          <span><span className="kbd"><CornerDownLeft size={10} /></span> open</span>
          <span><span className="kbd">Ctrl K</span> toggle</span>
        </div>
      </div>
    </div>
  );
}
