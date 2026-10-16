// Stripe webhook -> Supabase tier sync (runs on Vercel serverless).
// Uses the official stripe + @supabase/supabase-js packages.
// Env: STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.

import Stripe from "stripe";
import { createClient } from "@supabase/supabase-js";
import { buffer } from "micro";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export const config = { api: { bodyParser: false } };

const TIER = { FREEMIUM: 0, PRO: 1 };

async function setTier(email, tierCode, stripeCustomerId) {
  const { error } = await supabase.from("user_profiles").upsert(
    {
      email_address: email,
      subscription_tier_allocation: tierCode,
      stripe_customer_id: stripeCustomerId ?? undefined,
    },
    { onConflict: "email_address" }
  );
  if (error) throw new Error(`Supabase sync fault: ${error.message}`);
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method Not Allowed");

  let event;
  try {
    const rawBody = await buffer(req);
    const signature = req.headers["stripe-signature"];
    event = stripe.webhooks.constructEvent(
      rawBody,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    return res.status(400).send(`Webhook signature failure: ${err.message}`);
  }

  try {
    const obj = event.data.object;
    // Resolve the customer email (expandable; fallback to metadata).
    const email =
      obj.customer_email ||
      obj.metadata?.email ||
      (await stripe.customers
        .retrieve(obj.customer)
        .then((c) => c.email)
        .catch(() => null));

    if (!email) return res.status(200).json({ received: true, skipped: "no-email" });

    switch (event.type) {
      case "customer.subscription.created":
      case "customer.subscription.updated":
        if (obj.status === "active" || obj.status === "trialing") {
          await setTier(email, TIER.PRO, obj.customer);
        } else {
          await setTier(email, TIER.FREEMIUM, obj.customer);
        }
        break;
      case "customer.subscription.deleted":
        await setTier(email, TIER.FREEMIUM, obj.customer);
        break;
      default:
        break;
    }
    return res.status(200).json({ received: true });
  } catch (err) {
    console.error("tier sync error:", err);
    return res.status(500).send("Tier sync fault");
  }
}
