// The verifier page (index.html): all checking is done by js/spinproof-verify.mjs.
import { loadProof, NotCheckable, parseInput, passed, resultLine, verify } from './js/spinproof-verify.mjs';

const el = (id) => document.getElementById(id);
const form = el('form');

function show(proof, checks, fromPaste) {
    const good = passed(checks);
    const real = checks.filter((c) => c.status !== 'skip').length;
    el('seal').className = `seal ${good ? 'ok' : 'bad'}`;
    el('sealMark').textContent = good ? '✓' : '✗';
    el('summary').textContent = good ? `All ${real} checks passed` : 'This result does not match its lock';
    el('meta').textContent = good ? 'Nothing was changed after the lock.' : 'At least one check below did not pass.';

    const method = proof.drand ? 'Scheduled draw with drand randomness' : Number(proof.version || 1) === 2 ? 'Lock v2 (server secret + browser number)' : 'Lock v1 (server secret)';
    const facts = [
        ['Proof', proof.proof_url || proof.id],
        ['Title', `${proof.title || '–'} · spin ${proof.spin_number ?? '?'}`],
        ['Result', resultLine(proof) || '–'],
        ['Method', method],
        ['Locked', new Date(proof.locked_at).toLocaleString()],
    ];
    el('facts').replaceChildren(...facts.flatMap(([label, value]) => {
        const dt = document.createElement('dt');
        const dd = document.createElement('dd');
        dt.textContent = label;
        if (label === 'Proof' && /^https:\/\/spinproof\.app\/[rd]\//.test(value)) {
            dd.append(Object.assign(document.createElement('a'), { href: value, textContent: value, rel: 'noopener' }));
        } else {
            dd.textContent = value;
        }
        return [dt, dd];
    }));
    el('checks').replaceChildren(...checks.map((check) => Object.assign(document.createElement('li'), { className: check.status, textContent: check.text })));
    el('source').textContent = fromPaste
        ? 'Checked from the pasted record. Compare it with the live proof page to be sure it is the real one.'
        : 'Fetched from spinproof.app/api and checked here, in your browser.';
    el('result').hidden = false;
    el('result').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

async function run() {
    const error = el('error');
    error.textContent = '';
    el('result').hidden = true;
    const pasted = el('json').value.trim();
    const input = el('proof').value.trim();
    if (!pasted && !input) {
        error.textContent = 'Paste a proof link or its code first.';
        el('proof').focus();
        return;
    }
    el('go').disabled = true;
    el('go').textContent = 'Checking…';
    try {
        let proof;
        if (pasted) {
            proof = JSON.parse(pasted);
            if (proof.draw) proof = proof.draw.result;
            if (!proof) throw new NotCheckable('This scheduled draw has not happened yet.');
        } else {
            proof = await loadProof(...parseInput(input));
            history.replaceState(null, '', `?p=${encodeURIComponent(proof.id)}`);
        }
        show(proof, await verify(proof), !!pasted);
    } catch (problem) {
        error.textContent = problem instanceof NotCheckable ? problem.message
            : problem instanceof SyntaxError ? 'The pasted text is not valid JSON.'
                : `Could not check this proof: ${problem.message}`;
    } finally {
        el('go').disabled = false;
        el('go').textContent = 'Check';
    }
}

form.addEventListener('submit', (event) => {
    event.preventDefault();
    run();
});

// A link to this page can carry the proof: ?p=abc23xyz (or a whole proof link).
const preset = new URLSearchParams(location.search).get('p');
if (preset) {
    el('proof').value = preset;
    run();
}
