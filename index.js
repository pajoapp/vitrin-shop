// ویترین — Cloudflare Worker backend
// Bindings expected (wrangler.toml): DB (D1) — عکس‌ها هم داخل همین D1 (جدول media) ذخیره می‌شن، بدون نیاز به R2

const SESSION_DAYS = 30;
const COOKIE_NAME = "vitrin_session";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function err(message, status = 400) {
  return json({ error: message }, status);
}

// ---------- password hashing (PBKDF2, Web Crypto) ----------
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex
    ? hexToBytes(saltHex)
    : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}

// ---------- sessions ----------
function newToken() {
  return crypto.randomUUID() + crypto.randomUUID();
}

function parseCookies(req) {
  const header = req.headers.get("cookie") || "";
  return Object.fromEntries(
    header.split(";").filter(Boolean).map((c) => {
      const [k, ...v] = c.trim().split("=");
      return [k, decodeURIComponent(v.join("="))];
    })
  );
}

async function getSeller(req, env) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT s.* FROM sessions se JOIN sellers s ON s.id = se.seller_id
     WHERE se.token = ? AND se.expires_at > datetime('now')`
  ).bind(token).first();
  if (!row) return null;
  if (row.status === "suspended") return null;
  return row;
}

function sessionCookie(token) {
  const maxAge = SESSION_DAYS * 24 * 60 * 60;
  return `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

// ---------- plan features ----------
async function getPlanFeatures(seller, env) {
  const plan = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(seller.plan_id).first();
  if (!plan) return {};
  const list = plan.features ? JSON.parse(plan.features) : [];
  const map = {};
  for (const f of list) map[f.key] = f.value;
  return map;
}

// ---------- superadmin auth ----------
const ADMIN_COOKIE_NAME = "vitrin_admin_session";

async function getAdmin(req, env) {
  const cookies = parseCookies(req);
  const token = cookies[ADMIN_COOKIE_NAME];
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT a.* FROM admin_sessions se JOIN admins a ON a.id = se.admin_id
     WHERE se.token = ? AND se.expires_at > datetime('now')`
  ).bind(token).first();
  return row || null;
}

function adminSessionCookie(token) {
  const maxAge = SESSION_DAYS * 24 * 60 * 60;
  return `${ADMIN_COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

// ---------- router ----------
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    try {
      // ---- auth ----
      if (path === "/api/auth/register" && method === "POST") {
        const { username, phone, password, shop_name } = await req.json();
        if (!username || !phone || !password || !shop_name)
          return err("همه فیلدها لازم است");
        if (!/^[a-z0-9_]{3,20}$/.test(username))
          return err("نام کاربری فقط حروف انگلیسی کوچک، عدد و _ باشد (۳ تا ۲۰ کاراکتر)");

        const exists = await env.DB.prepare(
          "SELECT id FROM sellers WHERE username = ? OR phone = ?"
        ).bind(username, phone).first();
        if (exists) return err("این نام کاربری یا شماره قبلاً ثبت شده");

        const { hash, salt } = await hashPassword(password);
        const result = await env.DB.prepare(
          `INSERT INTO sellers (username, phone, password_hash, password_salt, shop_name)
           VALUES (?, ?, ?, ?, ?)`
        ).bind(username, phone, hash, salt, shop_name).run();

        const sellerId = result.meta.last_row_id;
        const token = newToken();
        await env.DB.prepare(
          `INSERT INTO sessions (token, seller_id, expires_at)
           VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
        ).bind(token, sellerId).run();

        const res = json({ ok: true, username });
        res.headers.append("Set-Cookie", sessionCookie(token));
        return res;
      }

      if (path === "/api/auth/login" && method === "POST") {
        const { phone, password } = await req.json();
        const seller = await env.DB.prepare(
          "SELECT * FROM sellers WHERE phone = ?"
        ).bind(phone).first();
        if (!seller) return err("شماره یا رمز اشتباه است", 401);

        const valid = await verifyPassword(password, seller.password_hash, seller.password_salt);
        if (!valid) return err("شماره یا رمز اشتباه است", 401);

        const token = newToken();
        await env.DB.prepare(
          `INSERT INTO sessions (token, seller_id, expires_at)
           VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
        ).bind(token, seller.id).run();

        const res = json({ ok: true, username: seller.username, shop_name: seller.shop_name });
        res.headers.append("Set-Cookie", sessionCookie(token));
        return res;
      }

      if (path === "/api/auth/logout" && method === "POST") {
        const cookies = parseCookies(req);
        const token = cookies[COOKIE_NAME];
        if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
        const res = json({ ok: true });
        res.headers.append("Set-Cookie", `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0`);
        return res;
      }

      if (path === "/api/auth/me" && method === "GET") {
        const seller = await getSeller(req, env);
        if (!seller) return err("وارد نشده‌اید", 401);
        return json({
          username: seller.username,
          shop_name: seller.shop_name,
          logo_url: seller.logo_url,
        });
      }

      // ---- everything below requires login ----
      if (path.startsWith("/api/admin/")) {
        const seller = await getSeller(req, env);
        if (!seller) return err("وارد نشده‌اید", 401);

        // list own products (with hidden/out-of-stock included)
        if (path === "/api/admin/products" && method === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT * FROM products WHERE seller_id = ? ORDER BY sort_order, id DESC"
          ).bind(seller.id).all();
          return json(results);
        }

        // create product
        if (path === "/api/admin/products" && method === "POST") {
          const p = await req.json();
          if (!p.name || p.price == null) return err("نام و قیمت لازم است");

          const features = await getPlanFeatures(seller, env);
          const hasVariants = Array.isArray(p.variants) && p.variants.length > 0;
          if (hasVariants && features.allow_variants === false)
            return err("پلن فعلی شما اجازهٔ سایز/رنگ چندگانه را نمی‌دهد — پلن را ارتقا دهید");

          if (features.max_products != null) {
            const { count } = await env.DB.prepare(
              "SELECT COUNT(*) as count FROM products WHERE seller_id = ?"
            ).bind(seller.id).first();
            if (count >= features.max_products)
              return err(`پلن فعلی شما حداکثر ${features.max_products} محصول را اجازه می‌دهد`);
          }

          const stock = hasVariants
            ? p.variants.reduce((s, v) => s + (Number(v.stock) || 0), 0)
            : (p.stock ?? 0);
          const status = stock > 0 ? "active" : "out_of_stock";
          const result = await env.DB.prepare(
            `INSERT INTO products (seller_id, name, description, price, image_url, variants, stock, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            seller.id, p.name, p.description || null, p.price,
            p.image_url || null, hasVariants ? JSON.stringify(p.variants) : null,
            stock, status
          ).run();
          return json({ ok: true, id: result.meta.last_row_id });
        }

        // update product (edit / change stock / hide / show)
        const editMatch = path.match(/^\/api\/admin\/products\/(\d+)$/);
        if (editMatch && method === "PUT") {
          const id = editMatch[1];
          const owned = await env.DB.prepare(
            "SELECT id FROM products WHERE id = ? AND seller_id = ?"
          ).bind(id, seller.id).first();
          if (!owned) return err("محصول پیدا نشد", 404);

          const p = await req.json();
          const hasVariants = Array.isArray(p.variants) && p.variants.length > 0;
          const stock = hasVariants
            ? p.variants.reduce((s, v) => s + (Number(v.stock) || 0), 0)
            : (p.stock ?? 0);
          const status = p.status || (stock > 0 ? "active" : "out_of_stock");
          await env.DB.prepare(
            `UPDATE products SET name=?, description=?, price=?, image_url=?, variants=?, stock=?, status=?
             WHERE id = ?`
          ).bind(
            p.name, p.description || null, p.price, p.image_url || null,
            hasVariants ? JSON.stringify(p.variants) : null, stock, status, id
          ).run();
          return json({ ok: true });
        }

        // delete product
        if (editMatch && method === "DELETE") {
          const id = editMatch[1];
          await env.DB.prepare(
            "DELETE FROM products WHERE id = ? AND seller_id = ?"
          ).bind(id, seller.id).run();
          return json({ ok: true });
        }

        // orders list
        if (path === "/api/admin/orders" && method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT o.*, p.name as product_name FROM orders o
             JOIN products p ON p.id = o.product_id
             WHERE o.seller_id = ? ORDER BY o.created_at DESC LIMIT 200`
          ).bind(seller.id).all();
          return json(results);
        }

        // stats
        if (path === "/api/admin/stats" && method === "GET") {
          const totals = await env.DB.prepare(
            `SELECT
               (SELECT COUNT(*) FROM orders WHERE seller_id = ?) as total_orders,
               (SELECT COUNT(*) FROM products WHERE seller_id = ? AND status != 'hidden') as active_products,
               (SELECT COALESCE(SUM(count),0) FROM shop_views WHERE seller_id = ?) as total_views`
          ).bind(seller.id, seller.id, seller.id).first();

          const top = await env.DB.prepare(
            `SELECT p.name, COUNT(o.id) as sold FROM orders o
             JOIN products p ON p.id = o.product_id
             WHERE o.seller_id = ? GROUP BY o.product_id ORDER BY sold DESC LIMIT 5`
          ).bind(seller.id).all();

          return json({ ...totals, top_products: top.results });
        }

        // update shop profile (name/logo)
        if (path === "/api/admin/profile" && method === "PUT") {
          const p = await req.json();
          await env.DB.prepare(
            "UPDATE sellers SET shop_name = ?, logo_url = ? WHERE id = ?"
          ).bind(p.shop_name, p.logo_url || null, seller.id).run();
          return json({ ok: true });
        }

        // upload a product image (already compressed client-side) — ذخیره در D1
        if (path === "/api/admin/upload" && method === "POST") {
          const features = await getPlanFeatures(seller, env);
          if (features.allow_image_upload === false)
            return err("پلن فعلی شما اجازهٔ آپلود عکس را نمی‌دهد — پلن را ارتقا دهید");

          const { data, ext } = await req.json(); // data = base64 (no data: prefix), ext = "jpg"
          if (!data) return err("تصویری ارسال نشده");
          const bytes = Uint8Array.from(atob(data), (c) => c.charCodeAt(0));
          if (bytes.length > 700 * 1024) return err("حجم عکس بیش از حد مجاز است");
          const id = crypto.randomUUID();
          const contentType = ext === "png" ? "image/png" : "image/jpeg";
          await env.DB.prepare(
            "INSERT INTO media (id, seller_id, content_type, data, size) VALUES (?, ?, ?, ?, ?)"
          ).bind(id, seller.id, contentType, bytes, bytes.length).run();
          return json({ ok: true, url: `/media/${id}` });
        }

        // seller's own plan info (name, features, current usage)
        if (path === "/api/admin/plan" && method === "GET") {
          const plan = await env.DB.prepare("SELECT * FROM plans WHERE id = ?").bind(seller.plan_id).first();
          const { count } = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM products WHERE seller_id = ?"
          ).bind(seller.id).first();
          return json({
            plan_name: plan?.name || "—",
            features: plan?.features ? JSON.parse(plan.features) : [],
            product_count: count,
          });
        }

        return err("مسیر نامعتبر", 404);
      }

      // ---- public: serve uploaded images (ذخیره‌شده در D1) ----
      if (path.startsWith("/media/") && method === "GET") {
        const id = path.replace("/media/", "");
        const row = await env.DB.prepare(
          "SELECT content_type, data FROM media WHERE id = ?"
        ).bind(id).first();
        if (!row) return err("تصویر پیدا نشد", 404);
        return new Response(row.data, {
          headers: {
            "content-type": row.content_type || "image/jpeg",
            "cache-control": "public, max-age=31536000, immutable",
          },
        });
      }

      // ---- public, read-only shop API ----
      const shopMatch = path.match(/^\/api\/shop\/([a-z0-9_]+)$/);
      if (shopMatch && method === "GET") {
        const username = shopMatch[1];
        const seller = await env.DB.prepare(
          "SELECT id, username, shop_name, logo_url FROM sellers WHERE username = ?"
        ).bind(username).first();
        if (!seller) return err("فروشگاه پیدا نشد", 404);

        const { results: products } = await env.DB.prepare(
          `SELECT id, name, description, price, image_url, variants, stock, status
           FROM products WHERE seller_id = ? AND status != 'hidden'
           ORDER BY sort_order, id DESC`
        ).bind(seller.id).all();

        // record a view (best-effort, non-blocking correctness not critical)
        const today = new Date().toISOString().slice(0, 10);
        await env.DB.prepare(
          `INSERT INTO shop_views (seller_id, day, count) VALUES (?, ?, 1)
           ON CONFLICT(seller_id, day) DO UPDATE SET count = count + 1`
        ).bind(seller.id, today).run();

        return json({ shop: seller, products });
      }

      // public: place an order (decrements stock)
      if (path === "/api/orders" && method === "POST") {
        const o = await req.json();
        if (!o.product_id || !o.quantity) return err("اطلاعات سفارش ناقص است");

        const product = await env.DB.prepare(
          "SELECT * FROM products WHERE id = ?"
        ).bind(o.product_id).first();
        if (!product) return err("محصول پیدا نشد", 404);

        let variants = product.variants ? JSON.parse(product.variants) : null;

        if (variants && variants.length) {
          if (!o.variant) return err("انتخاب سایز/رنگ لازم است");
          const idx = variants.findIndex((v) => `${v.size || ""}${v.size && v.color ? " / " : ""}${v.color || ""}` === o.variant);
          if (idx === -1) return err("گزینه انتخابی پیدا نشد");
          if (variants[idx].stock < o.quantity) return err("موجودی کافی نیست", 409);

          variants[idx].stock -= o.quantity;
          const totalStock = variants.reduce((s, v) => s + v.stock, 0);
          const newStatus = totalStock <= 0 ? "out_of_stock" : product.status;

          await env.DB.batch([
            env.DB.prepare("UPDATE products SET variants = ?, stock = ?, status = ? WHERE id = ?")
              .bind(JSON.stringify(variants), totalStock, newStatus, product.id),
            env.DB.prepare(
              `INSERT INTO orders (seller_id, product_id, variant, quantity, buyer_name, buyer_phone, note)
               VALUES (?, ?, ?, ?, ?, ?, ?)`
            ).bind(
              product.seller_id, product.id, o.variant, o.quantity,
              o.buyer_name || null, o.buyer_phone || null, o.note || null
            ),
          ]);
          return json({ ok: true });
        }

        // no variants — simple stock
        if (product.stock < o.quantity) return err("موجودی کافی نیست", 409);
        const newStock = product.stock - o.quantity;
        const newStatus = newStock <= 0 ? "out_of_stock" : product.status;
        await env.DB.batch([
          env.DB.prepare("UPDATE products SET stock = ?, status = ? WHERE id = ?")
            .bind(newStock, newStatus, product.id),
          env.DB.prepare(
            `INSERT INTO orders (seller_id, product_id, variant, quantity, buyer_name, buyer_phone, note)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            product.seller_id, product.id, o.variant || null, o.quantity,
            o.buyer_name || null, o.buyer_phone || null, o.note || null
          ),
        ]);
        return json({ ok: true });
      }

      // ================= SUPERADMIN =================

      // one-time bootstrap: create the first (and only, unless more added later) admin account
      if (path === "/api/superadmin/setup" && method === "POST") {
        const { setup_key, username, password } = await req.json();
        if (!env.SETUP_KEY || setup_key !== env.SETUP_KEY)
          return err("کلید راه‌اندازی نامعتبر است", 403);

        const { count } = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
        if (count > 0) return err("پنل مدیر کل قبلاً راه‌اندازی شده — از فرم ورود استفاده کن", 409);
        if (!username || !password || password.length < 6)
          return err("نام کاربری و رمز (حداقل ۶ کاراکتر) لازم است");

        const { hash, salt } = await hashPassword(password);
        await env.DB.prepare(
          "INSERT INTO admins (username, password_hash, password_salt) VALUES (?, ?, ?)"
        ).bind(username, hash, salt).run();
        return json({ ok: true });
      }

      if (path === "/api/superadmin/login" && method === "POST") {
        const { username, password } = await req.json();
        const admin = await env.DB.prepare("SELECT * FROM admins WHERE username = ?").bind(username).first();
        if (!admin) return err("نام کاربری یا رمز اشتباه است", 401);
        const valid = await verifyPassword(password, admin.password_hash, admin.password_salt);
        if (!valid) return err("نام کاربری یا رمز اشتباه است", 401);

        const token = newToken();
        await env.DB.prepare(
          `INSERT INTO admin_sessions (token, admin_id, expires_at)
           VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
        ).bind(token, admin.id).run();

        const res = json({ ok: true, username: admin.username });
        res.headers.append("Set-Cookie", adminSessionCookie(token));
        return res;
      }

      if (path === "/api/superadmin/logout" && method === "POST") {
        const cookies = parseCookies(req);
        const token = cookies[ADMIN_COOKIE_NAME];
        if (token) await env.DB.prepare("DELETE FROM admin_sessions WHERE token = ?").bind(token).run();
        const res = json({ ok: true });
        res.headers.append("Set-Cookie", `${ADMIN_COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0`);
        return res;
      }

      if (path === "/api/superadmin/needs-setup" && method === "GET") {
        const { count } = await env.DB.prepare("SELECT COUNT(*) as count FROM admins").first();
        return json({ needs_setup: count === 0 });
      }

      if (path === "/api/superadmin/me" && method === "GET") {
        const admin = await getAdmin(req, env);
        if (!admin) return err("وارد نشده‌اید", 401);
        return json({ username: admin.username });
      }

      // ---- everything below requires admin login ----
      if (path.startsWith("/api/superadmin/")) {
        const admin = await getAdmin(req, env);
        if (!admin) return err("وارد نشده‌اید", 401);

        // platform-wide stats
        if (path === "/api/superadmin/stats" && method === "GET") {
          const totals = await env.DB.prepare(
            `SELECT
               (SELECT COUNT(*) FROM sellers) as total_sellers,
               (SELECT COUNT(*) FROM sellers WHERE status = 'active') as active_sellers,
               (SELECT COUNT(*) FROM products) as total_products,
               (SELECT COUNT(*) FROM orders) as total_orders`
          ).first();
          return json(totals);
        }

        // list sellers with plan name
        if (path === "/api/superadmin/sellers" && method === "GET") {
          const { results } = await env.DB.prepare(
            `SELECT s.id, s.username, s.shop_name, s.phone, s.status, s.created_at,
                    p.id as plan_id, p.name as plan_name,
                    (SELECT COUNT(*) FROM products WHERE seller_id = s.id) as product_count,
                    (SELECT COUNT(*) FROM orders WHERE seller_id = s.id) as order_count
             FROM sellers s LEFT JOIN plans p ON p.id = s.plan_id
             ORDER BY s.created_at DESC`
          ).all();
          return json(results);
        }

        // update a seller: change plan and/or status
        const sellerMatch = path.match(/^\/api\/superadmin\/sellers\/(\d+)$/);
        if (sellerMatch && method === "PUT") {
          const id = sellerMatch[1];
          const b = await req.json();
          const updates = [];
          const binds = [];
          if (b.plan_id != null) { updates.push("plan_id = ?"); binds.push(b.plan_id); }
          if (b.status) { updates.push("status = ?"); binds.push(b.status); }
          if (!updates.length) return err("چیزی برای تغییر ارسال نشده");
          binds.push(id);
          await env.DB.prepare(`UPDATE sellers SET ${updates.join(", ")} WHERE id = ?`).bind(...binds).run();
          return json({ ok: true });
        }

        // delete a seller (cascades to their products/orders/sessions)
        if (sellerMatch && method === "DELETE") {
          await env.DB.prepare("DELETE FROM sellers WHERE id = ?").bind(sellerMatch[1]).run();
          return json({ ok: true });
        }

        // plans: list (all, including inactive, for management)
        if (path === "/api/superadmin/plans" && method === "GET") {
          const { results } = await env.DB.prepare(
            "SELECT * FROM plans ORDER BY sort_order, id"
          ).all();
          return json(results.map(p => ({ ...p, features: p.features ? JSON.parse(p.features) : [] })));
        }

        // plans: create
        if (path === "/api/superadmin/plans" && method === "POST") {
          const p = await req.json();
          if (!p.key || !p.name) return err("کلید و نام پلن لازم است");
          const result = await env.DB.prepare(
            `INSERT INTO plans (key, name, price, billing_period, is_active, sort_order, features)
             VALUES (?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            p.key, p.name, p.price || 0, p.billing_period || "monthly",
            p.is_active ? 1 : 0, p.sort_order || 0, JSON.stringify(p.features || [])
          ).run();
          return json({ ok: true, id: result.meta.last_row_id });
        }

        // plans: update
        const planMatch = path.match(/^\/api\/superadmin\/plans\/(\d+)$/);
        if (planMatch && method === "PUT") {
          const p = await req.json();
          await env.DB.prepare(
            `UPDATE plans SET name=?, price=?, billing_period=?, is_active=?, sort_order=?, features=?
             WHERE id = ?`
          ).bind(
            p.name, p.price || 0, p.billing_period || "monthly",
            p.is_active ? 1 : 0, p.sort_order || 0, JSON.stringify(p.features || []), planMatch[1]
          ).run();
          return json({ ok: true });
        }

        // plans: delete (only if no seller currently on it)
        if (planMatch && method === "DELETE") {
          const inUse = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM sellers WHERE plan_id = ?"
          ).bind(planMatch[1]).first();
          if (inUse.count > 0) return err("این پلن هنوز فروشنده فعال دارد — اول فروشنده‌ها را جابه‌جا کن");
          await env.DB.prepare("DELETE FROM plans WHERE id = ?").bind(planMatch[1]).run();
          return json({ ok: true });
        }

        return err("مسیر نامعتبر", 404);
      }

      // ================= end superadmin =================

      return err("مسیر پیدا نشد", 404);
    } catch (e) {
      return err("خطای سرور: " + e.message, 500);
    }
  },
};
