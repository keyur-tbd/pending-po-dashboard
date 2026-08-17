/**
 * GET /api/po-data          -> the dashboard's data, cached 15 minutes
 * GET /api/po-data?debug=1  -> what this function can actually see in your sheet
 *
 * Authenticates as a Google service account. The sheet is shared to that
 * account's email address the same way you'd share it with a colleague, so the
 * sheet itself can stay private -- link-sharing can be turned off entirely.
 *
 * No npm packages. JWT signing uses Node's built-in crypto module, so there is
 * still no package.json, no install step and nothing that can fail at build.
 *
 * Environment variables (Vercel -> Settings -> Environment Variables):
 *   SHEETS_ID               the long id in your sheet URL, between /d/ and /edit
 *   GOOGLE_SA_EMAIL         client_email from the service account JSON key
 *   GOOGLE_SA_PRIVATE_KEY   private_key from that same JSON, the whole PEM block
 *
 * If ?debug=1 shows an auth error, it is almost always the private key.
 * See normalisePrivateKey() below -- it handles the common paste mistakes.
 */

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// 1. TAB NAMES
// Put your real tab names on the right. Matching ignores case, spaces,
// underscores and hyphens, so "PO Lines", "po_lines" and "polines" all match.
// If a tab is missing the dashboard still loads, minus that section.
// ---------------------------------------------------------------------------
const TABS = {
  // --- confirmed from your sheet "Pending POs" ---
  poLines:        'Uni-Commerce Data',            // the PO line extract
  items:          'Carton & MRP',                 // item code, name, mrp, carton
  itemCat:        'Item code & Category Master',  // item code -> category
  platformMaster: 'Channel And Platform Master',  // name, city, display name, channel, city type
  warehouses:     'WH Master',                    // warehouse code -> name

  // --- NOT yet confirmed ---
  // Nothing in your sheet is obviously the PO / SO / Invoice / GRN fill-rate
  // data. Candidates are "Report Format" and "D vs S". Set this to whichever
  // one holds it. Leaving it wrong is harmless: the dashboard still loads and
  // the billing/fill-rate section simply stays empty.
  fillRate:       'Fill Rate'
};

// ---------------------------------------------------------------------------
// 2. COLUMN NAMES
// Left = a header as it might appear in your sheet (normalised).
// Right = the field name the dashboard already expects. Add lines as needed;
// run ?debug=1 to see exactly which headers your sheet is sending.
// ---------------------------------------------------------------------------
const FIELD_ALIASES = {
  poLines: {
    warehouse: 'wh', whname: 'wh',
    ponumber: 'orderId', ponum: 'orderId', orderid: 'orderId',
    appointmentdate: 'apptDate', apptdate: 'apptDate',
    postingdate: 'postingDate', orderdate: 'orderDate', podate: 'orderDate',
    customercode: 'custCode', customerreference: 'custRef',
    shipto: 'shipTo', shiptocode: 'shipTo',
    itemcode: 'item', sku: 'item', skucode: 'item',
    povalue: 'value', value: 'value', amount: 'value',
    poqty: 'qty', quantity: 'qty', qty: 'qty',
    invoiceno: 'invoiceNo', facility: 'facility', channel: 'channel', mrp: 'mrp'
  },
  fillRate: {
    warehousecode: 'whCode', warehouse: 'wh',
    itemcode: 'item', itemname: 'itemName',
    povalue: 'poVal', sovalue: 'soVal', invoicevalue: 'invVal', grnvalue: 'grnVal',
    poquantity: 'poQty', soquantity: 'soQty',
    invoicequantity: 'invQty', grnquantity: 'grnQty',
    ponumber: 'poNum', sonumber: 'soNum', invoiceno: 'invNum',
    podate: 'poDate', sodate: 'soDate', invoicedate: 'invDate',
    potype: 'poType', customer: 'customer', shipto: 'shipTo',
    channel: 'channel', category: 'category', mrp: 'mrp'
  }
};

const NUMERIC = new Set([
  'value', 'qty', 'mrp', 'carton',
  'poVal', 'soVal', 'invVal', 'grnVal',
  'poQty', 'soQty', 'invQty', 'grnQty'
]);

const CACHE_SECONDS = 900;   // CDN keeps the response 15 minutes
const STALE_SECONDS = 3600;  // and may serve it stale for an hour while refreshing

const SCOPE = 'https://www.googleapis.com/auth/spreadsheets.readonly';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

/**
 * Environment variables cannot hold real newlines in most UIs, so a pasted PEM
 * arrives in one of several mangled forms. This puts it back together:
 *   - literal backslash-n instead of newlines (the usual case)
 *   - wrapped in quotes, because it was copied straight out of the JSON file
 *   - Windows line endings
 *   - all whitespace stripped, so BEGIN/END sit flush against the base64
 *
 * The last one is the nastiest: it still contains the words BEGIN and
 * PRIVATE KEY, so it passes a naive shape check, then fails deep inside
 * OpenSSL with an unhelpful "DECODER routines::unsupported". So rather than
 * patching up whitespace, this pulls out the base64 payload and rebuilds the
 * PEM from scratch. Whatever went in, a correctly formed PEM comes out.
 */
function normalisePrivateKey(raw) {
  let k = String(raw || '').trim();

  if ((k.startsWith('"') && k.endsWith('"')) || (k.startsWith("'") && k.endsWith("'"))) {
    k = k.slice(1, -1);
  }
  k = k.replace(/\\n/g, '\n').replace(/\\r/g, '').replace(/\r/g, '');

  // What kind of key is it? Google issues PKCS#8 ("PRIVATE KEY"), but accept
  // the traditional RSA form too rather than silently mangling it.
  const label = /BEGIN\s+RSA\s+PRIVATE\s+KEY/i.test(k) ? 'RSA PRIVATE KEY' : 'PRIVATE KEY';

  // Strip every marker and all whitespace, leaving just the base64 payload.
  const body = k
    .replace(/-{2,}\s*(BEGIN|END)[A-Z\s]*-{2,}/gi, '')
    .replace(/\s+/g, '');

  if (!body) return k;

  // Rebuild with the payload wrapped at 64 characters, which is what PEM
  // requires and what OpenSSL refuses to work without.
  const lines = body.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

const b64url = (buf) => Buffer.from(buf)
  .toString('base64')
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Cached across warm invocations so we don't mint a token on every request. */
let tokenCache = { value: null, expiresAt: 0 };

async function getAccessToken(email, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  if (tokenCache.value && tokenCache.expiresAt - 60 > now) return tokenCache.value;

  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = { iss: email, scope: SCOPE, aud: TOKEN_URL, iat: now, exp: now + 3600 };
  const signingInput = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(claims));

  let signature;
  try {
    signature = crypto.createSign('RSA-SHA256').update(signingInput).sign(privateKey);
  } catch (err) {
    const e = new Error(
      'The service account private key could not be used to sign a token. Check that '
      + 'GOOGLE_SA_PRIVATE_KEY contains the whole PEM block, including the BEGIN and END lines. '
      + 'Underlying error: ' + (err && err.message ? err.message : String(err))
    );
    e.authStage = 'signing';
    throw e;
  }

  const assertion = signingInput + '.' + b64url(signature);

  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion
    }).toString()
  });

  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.access_token) {
    const e = new Error('Google refused to issue an access token. '
      + (body.error_description || body.error || ('HTTP ' + res.status)));
    e.authStage = 'token';
    e.googleError = body.error || null;
    throw e;
  }

  tokenCache = { value: body.access_token, expiresAt: now + (Number(body.expires_in) || 3600) };
  return tokenCache.value;
}

// ---------------------------------------------------------------------------
// Sheet parsing
// ---------------------------------------------------------------------------

const norm = (s) => String(s == null ? '' : s).toLowerCase().replace(/[\s_\-./]/g, '');

const toNumber = (v) => {
  if (v === null || v === undefined || v === '') return 0;
  const n = Number(String(v).replace(/[,\s]/g, '').replace(/[^\d.\-]/g, ''));
  return Number.isFinite(n) ? n : 0;
};

function rowsToObjects(grid, aliases) {
  aliases = aliases || {};
  if (!Array.isArray(grid) || grid.length < 2) return [];
  const headers = grid[0].map((h) => {
    const k = norm(h);
    return aliases[k] || k;
  });
  return grid.slice(1)
    .filter((row) => row.some((c) => String(c == null ? '' : c).trim() !== ''))
    .map((row) => {
      const o = {};
      headers.forEach((key, i) => {
        if (!key) return;
        const raw = row[i] === undefined ? '' : row[i];
        o[key] = NUMERIC.has(key) ? toNumber(raw) : String(raw).trim();
      });
      return o;
    });
}

// ---------------------------------------------------------------------------

module.exports = async (req, res) => {
  const debug = req.query && (req.query.debug === '1' || req.query.debug === 'true');

  const sheetId = process.env.SHEETS_ID;
  const saEmail = process.env.GOOGLE_SA_EMAIL;
  const saKeyRaw = process.env.GOOGLE_SA_PRIVATE_KEY;

  const missing = [
    !sheetId && 'SHEETS_ID',
    !saEmail && 'GOOGLE_SA_EMAIL',
    !saKeyRaw && 'GOOGLE_SA_PRIVATE_KEY'
  ].filter(Boolean);

  if (missing.length) {
    res.status(500).json({
      error: 'Sheet connection is not configured.',
      missing,
      detail: 'Add these in Vercel under Settings > Environment Variables, then redeploy. '
            + 'Variables are read at deploy time, so adding them without redeploying changes nothing.'
    });
    return;
  }

  const privateKey = normalisePrivateKey(saKeyRaw);

  // Cheap shape check before we bother Google with it.
  if (!privateKey.includes('BEGIN') || !privateKey.includes('PRIVATE KEY')) {
    res.status(500).json({
      error: 'GOOGLE_SA_PRIVATE_KEY does not look like a PEM key.',
      detail: 'It should start with -----BEGIN PRIVATE KEY----- and end with -----END PRIVATE KEY-----. '
            + 'Copy the private_key value out of the service account JSON file, including both of those lines.',
      starts_with: privateKey.slice(0, 30)
    });
    return;
  }

  try {
    // --- Step 0: authenticate ---
    let token;
    try {
      token = await getAccessToken(saEmail, privateKey);
    } catch (err) {
      res.status(502).json({
        error: 'Could not authenticate as the service account.',
        stage: err.authStage || 'unknown',
        detail: err.message,
        hint: err.authStage === 'signing'
          ? 'The private key is malformed. Re-copy it from the JSON key file.'
          : err.googleError === 'invalid_grant'
          ? 'The key may have been deleted or the service account disabled. Check it still exists in Google Cloud.'
          : 'Check GOOGLE_SA_EMAIL matches client_email in the JSON key file exactly.'
      });
      return;
    }

    const auth = { headers: { Authorization: 'Bearer ' + token } };

    // --- Step 1: what tabs does this spreadsheet actually have? ---
    const metaUrl = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}`
                  + `?fields=properties.title,sheets.properties.title`;
    const metaRes = await fetch(metaUrl, auth);
    if (!metaRes.ok) {
      const body = await metaRes.text();
      res.status(502).json({
        error: 'Google would not open the spreadsheet.',
        status: metaRes.status,
        detail: body.slice(0, 600),
        share_this_sheet_with: saEmail,
        hint: (metaRes.status === 403 || metaRes.status === 404)
          ? 'The service account has almost certainly not been given access to the sheet. Open the sheet, '
            + 'click Share, and add the address above as a Viewer. Also confirm SHEETS_ID is correct.'
          : 'Check SHEETS_ID and that the Google Sheets API is enabled on the project.'
      });
      return;
    }
    const meta = await metaRes.json();
    const actualTabs = (meta.sheets || []).map((s) => s.properties.title);

    // --- Step 2: match configured tab names to real ones, forgivingly ---
    const matched = {}, unmatched = [];
    Object.keys(TABS).forEach((block) => {
      const want = norm(TABS[block]);
      const hit = actualTabs.find((t) => norm(t) === want)
               || actualTabs.find((t) => norm(t).includes(want) || want.includes(norm(t)));
      if (hit) matched[block] = hit; else unmatched.push({ block, looking_for: TABS[block] });
    });

    // --- Step 3: read whatever tabs did match, in one call ---
    // NOTE: the "PO Lines missing" check deliberately happens AFTER this, so
    // that ?debug=1 still works when a tab name is wrong. That is exactly the
    // moment you need it most.
    const blocks = Object.keys(matched);
    const grids = {};

    if (blocks.length) {
      const qs = blocks.map((b) => `ranges=${encodeURIComponent(matched[b])}`).join('&');
      const valUrl = `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values:batchGet`
                   + `?${qs}&majorDimension=ROWS`;
      const valRes = await fetch(valUrl, auth);
      if (!valRes.ok) {
        const body = await valRes.text();
        res.status(502).json({
          error: 'Google Sheets rejected the data request.',
          status: valRes.status,
          detail: body.slice(0, 600)
        });
        return;
      }
      const val = await valRes.json();
      blocks.forEach((b, i) => {
        grids[b] = (val.valueRanges && val.valueRanges[i] && val.valueRanges[i].values) || [];
      });
    }

    // --- Debug view: show what came back, before any reshaping ---
    if (debug) {
      const view = {};
      blocks.forEach((b) => {
        const g = grids[b];
        view[b] = {
          tab: matched[b],
          rows_after_header: Math.max(0, g.length - 1),
          headers_in_sheet: g[0] || [],
          headers_after_mapping: (g[0] || []).map((h) => (FIELD_ALIASES[b] || {})[norm(h)] || norm(h)),
          first_row: g[1] || null
        };
      });
      res.setHeader('Cache-Control', 'no-store');
      res.status(200).json({
        auth: { mode: 'service account', signed_in_as: saEmail },
        spreadsheet: meta.properties && meta.properties.title,
        tabs_in_your_sheet: actualTabs,
        matched, unmatched, blocks: view,
        what_the_dashboard_needs: {
          poLines: ['wh', 'orderId', 'channel', 'apptDate', 'orderDate', 'item', 'value', 'qty', 'mrp', 'custCode', 'shipTo', 'custRef'],
          note: 'Any name under headers_after_mapping that is not in this list is ignored, not an error. '
              + 'A missing name from this list means you need an alias in FIELD_ALIASES.'
        }
      });
      return;
    }

    // --- Step 3b: the one tab we cannot do without ---
    // `detail` carries the tab list because that is the field the dashboard's
    // error screen displays. Putting it only in a side field means the person
    // staring at the error never sees the answer.
    if (!matched.poLines) {
      res.status(422).json({
        error: 'Could not find the PO Lines tab.',
        detail: 'Looking for a tab named "' + TABS.poLines + '". The tabs in your sheet are: '
              + (actualTabs.length ? actualTabs.map((t) => '"' + t + '"').join(', ') : '(none found)')
              + '. Edit the TABS block at the top of api/po-data.js so poLines matches one of these, then redeploy.',
        looking_for: TABS.poLines,
        tabs_in_your_sheet: actualTabs,
        also_unmatched: unmatched
      });
      return;
    }

    // --- Step 4: reshape into what the dashboard expects ---
    const poLines = rowsToObjects(grids.poLines, FIELD_ALIASES.poLines);
    const fillRate = rowsToObjects(grids.fillRate, FIELD_ALIASES.fillRate);
    const itemRows = rowsToObjects(grids.items);
    const catRows = rowsToObjects(grids.itemCat);

    const items = {};
    itemRows.forEach((r) => {
      const code = r.itemcode || r.item || r.code || r.sku;
      if (!code) return;
      items[code] = {
        name: r.itemname || r.name || code,
        mrp: toNumber(r.mrp),
        category: r.category || '',
        carton: toNumber(r.carton !== undefined ? r.carton : r.cartonsize)
      };
    });

    const itemCat = {};
    catRows.forEach((r) => {
      const code = r.itemcode || r.item || r.code || r.sku;
      if (code) itemCat[code] = r.category || r.reportingcategory || '';
    });

    // Warehouses: prefer the WH Master tab if it has usable rows, otherwise
    // fall back to whatever actually appears in the PO lines. The fallback
    // means a new WH going live is never invisible, even if the master lags.
    const whRows = rowsToObjects(grids.warehouses);
    let warehouses = whRows
      .map((r) => {
        const code = r.warehousecode || r.whcode || r.code || r.warehouse || '';
        const name = r.warehousename || r.whname || r.name || code;
        return code || name ? { code: code || name, name: name || code } : null;
      })
      .filter(Boolean);

    if (!warehouses.length) {
      warehouses = [...new Set(poLines.map((l) => l.wh).filter(Boolean))]
        .sort().map((name) => ({ code: name, name }));
    }

    const platformMaster = (grids.platformMaster || []).slice(1)
      .filter((row) => row.some((c) => String(c == null ? '' : c).trim() !== ''));

    res.setHeader('Cache-Control',
      `public, max-age=0, s-maxage=${CACHE_SECONDS}, stale-while-revalidate=${STALE_SECONDS}`);

    res.status(200).json({
      fetchedAt: new Date().toISOString(),
      warehouses, items, itemCat, poLines, fillRate, platformMaster,
      _counts: {
        poLines: poLines.length,
        fillRate: fillRate.length,
        items: Object.keys(items).length,
        platformMaster: platformMaster.length
      }
    });
  } catch (err) {
    res.status(502).json({
      error: 'Could not reach Google Sheets.',
      detail: String(err && err.message ? err.message : err)
    });
  }
};
