import type {
  CashuPaymentInfo,
  Hexpubkey,
  LnPaymentInfo,
  NDKFilter,
  NDKNutzap,
  NDKPaymentConfirmationCashu,
  NDKZapDetails,
  NDKSubscription,
  NDKSubscriptionOptions,
  NDKRelay,
  NDKPaymentConfirmationLN,
  NDKTag,
} from "@nostr-dev-kit/ndk";
import NDK, {
  NDKEvent,
  NDKKind,
  NDKPrivateKeySigner,
  NDKRelaySet,
  NDKSubscriptionCacheUsage,
} from "@nostr-dev-kit/ndk";
import { NDKCashuDeposit } from "../deposit.js";
import type { MintUrl } from "../mint/utils.js";
import { CashuWallet, Proof, SendResponse } from "@cashu/cashu-ts";
import { getDecodedToken } from "@cashu/cashu-ts";
import { consolidateMintTokens, consolidateTokens } from "../validate.js";
import {
  NDKWallet,
  NDKWalletBalance,
  NDKWalletStatus,
  NDKWalletTypes,
  RedeemNutzapsOpts,
} from "../../index.js";
import { eventDupHandler, eventHandler } from "../event-handlers/index.js";
import { NDKCashuDepositMonitor } from "../deposit-monitor.js";

export type WalletWarning = {
  msg: string;
  event?: NDKEvent;
  relays?: NDKRelay[];
};

import { PaymentHandler, PaymentWithOptionalZapInfo } from "./payment.js";
import { createInTxEvent, createOutTxEvent } from "./txs.js";
import { WalletState } from "./state/index.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { DeterministicCashuWalletInfoKind, isDeterministicCashuWalletInfoContent } from "./deterministic-info.js";
import { walletForMint } from "../mint.js";

export { DeterministicCashuWalletInfoKind };

export type RestoreWalletOpts = {
  gapLimit?: number,
  batchSize?: number,
  startCounter?: number,
  activeKeysets?: boolean
}

export type RecoverResult = {
  unspent?: Proof[],
  spent?: string[]
}

/**
 * This class tracks state of a NIP-60 wallet
 */
export class NDKCashuWallet extends NDKWallet {
  get type(): NDKWalletTypes {
    return "nip-60";
  }

  private _bip39seed?: Uint8Array;
  public _p2pk: string | undefined;
  private sub?: NDKSubscription;

  public status: NDKWalletStatus = NDKWalletStatus.INITIAL;

  static kind = NDKKind.CashuWallet;
  static kinds = [NDKKind.CashuWallet];

  public mints: string[] = [];
  public privkeys = new Map<string, NDKPrivateKeySigner>();
  public signer?: NDKPrivateKeySigner;

  public _event?: NDKEvent;

  public walletId: string = "nip-60";

  public depositMonitor = new NDKCashuDepositMonitor();

  /**
   * Warnings that have been raised
   */
  public warnings: WalletWarning[] = [];

  private paymentHandler: PaymentHandler;
  public state: WalletState;

  public relaySet?: NDKRelaySet;

  private async publishReplaceableWithTimeout(
    event: NDKEvent,
    relaySet?: NDKRelaySet,
    timeoutMs = 8000
  ): Promise<Set<NDKRelay>> {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<Set<NDKRelay>>((resolve) => {
      timeoutId = setTimeout(() => {
        console.warn("[wallet] publishReplaceable timed out", {
          kind: event.kind,
          timeoutMs,
        });
        resolve(new Set<NDKRelay>());
      }, timeoutMs);
    });

    try {
      const result = await Promise.race([event.publishReplaceable(relaySet), timeoutPromise]);
      if (timeoutId) clearTimeout(timeoutId);
      return result;
    } catch (error) {
      if (timeoutId) clearTimeout(timeoutId);
      console.warn("[wallet] publishReplaceable failed", { kind: event.kind, error });
      return new Set<NDKRelay>();
    }
  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    label: string
  ): Promise<T | undefined> {
    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    try {
      const timeoutPromise = new Promise<undefined>((resolve) => {
        timeoutId = setTimeout(() => {
          console.warn(`${label} timed out after ${timeoutMs}ms.`);
          resolve(undefined);
        }, timeoutMs);
      });

      return (await Promise.race([promise, timeoutPromise])) as T | undefined;
    } catch (error) {
      console.warn(`${label} failed.`, error);
      return undefined;
    } finally {
      if (timeoutId) clearTimeout(timeoutId);
    }
  }

  constructor(ndk: NDK, bip39seed?: Uint8Array, event?: NDKEvent) {
    super(ndk);
    if (!event) {
      event = new NDKEvent(ndk);
      event.kind = NDKKind.CashuWallet;
      event.tags = [];
    }

    this.event = event;
    this.ndk = ndk;
    this._bip39seed = bip39seed;
    this.paymentHandler = new PaymentHandler(this);
    // Initialize WalletState with an empty counters snapshot
    this.state = new WalletState(this, new Set<string>());
  }

  public get bip39seed(): Uint8Array | undefined {
    return this._bip39seed;
  }

  public set bip39seed(value: Uint8Array) {
    this._bip39seed = value;
  }

  set event(e: NDKEvent | undefined) {
    this._event = e;
  }

  get event(): NDKEvent | undefined {
    return this._event;
  }

  /**
   * Generates a backup event for this wallet
   */
  async backup(publish = true) {
    if (!this.event) throw new Error("wallet event not available");

    // check if we have a key to backup
    if (this.privkeys.size === 0) throw new Error("no privkey to backup");

    const backup = new NDKCashuWalletBackup(this.ndk);

    const privkeys: string[] = [];
    for (const signer of this.privkeys.values()) {
      privkeys.push(signer.privateKey!);
    }

    backup.privkeys = privkeys;
    backup.mints = this.mints;
    if (publish) backup.save(this.relaySet);

    return backup;
  }

  tagId() {
    return this.event?.tagId();
  }

  public consolidateTokens = consolidateTokens.bind(this);

  /**
   * Generates nuts that can be used to send to someone.
   *
   * Note that this function does not send anything, it just generates a specific amount of proofs.
   * @param amounts
   * @returns
   */
  async mintNuts(amounts: number[]) {
    let result: SendResponse | undefined;
    const totalAmount = amounts.reduce((acc, amount) => acc + amount, 0);

    for (const mint of this.mints) {
      const wallet = await this.getCashuWallet(mint, this._bip39seed);
      const mintProofs = this.state.getProofs({ mint });
      const currentCounterEntry = await this.state.getCounterEntryFor(wallet.mint);
      const counter = this._bip39seed ? currentCounterEntry.counter ?? 0 : undefined;
      result = await wallet.send(totalAmount, mintProofs, {
        proofsWeHave: mintProofs,
        includeFees: true,
        outputAmounts: {
          sendAmounts: amounts,
        },
        counter
      });

      if (result.send.length > 0) {
        const change = { store: result?.keep ?? [], destroy: result.send, mint };
        const updateRes = await this.state.update(change);

        if (this._bip39seed) {
          // Increment deterministic counters for active keyset (all new outputs: send + change)
          const outputsCount = result.send.length + (result.keep?.length ?? 0);
          outputsCount && await this.incrementDeterministicCounter(currentCounterEntry.counterKey, outputsCount);
        }

        // create a change event
        createOutTxEvent(
          this.ndk,
          {
            paymentDescription: "minted nuts",
            amount: amounts.reduce((acc, amount) => acc + amount, 0),
          },
          {
            result: { proofs: result.send, mint },
            proofsChange: change,
            stateUpdate: updateRes,
            mint,
            fee: 0,
          },
          this.relaySet
        );
        this.emit("balance_updated");

        return result;
      }
    }
  }

  static async from(
    event: NDKEvent,
    deterministicInfoEvent?: NDKEvent,
    decryptedContent?: string,
    decryptedDeterministicContent?: string
  ): Promise<NDKCashuWallet | undefined> {
    const logPrefix = "[wallet:from]";
    console.warn(`${logPrefix} start`, {
      kind: event.kind,
      pubkey: event.pubkey,
      hasNdk: Boolean(event.ndk),
      hasDeterministic: Boolean(deterministicInfoEvent),
      decryptedProvided: Boolean(decryptedContent),
      contentLength: typeof event.content === "string" ? event.content.length : 0,
    });
    if (!event.ndk) throw new Error("no ndk instance on event");
    const wallet = new NDKCashuWallet(event.ndk, undefined, event);

    if (!wallet.event) {
      console.warn(`${logPrefix} abort`, { reason: "missing event" });
      return;
    }
    if (wallet.isDeleted) {
      console.warn(`${logPrefix} abort`, { reason: "event deleted" });
      return;
    }

    if (decryptedContent) {
      wallet.event.content = decryptedContent;
      console.warn(`${logPrefix} using provided decrypted content`, {
        length: decryptedContent.length,
      });
    } else {
      const isNip46Signer = Boolean(
        wallet.ndk.signer?.constructor?.name?.includes("Nip46")
      );
      let walletDecryptOk = false;
      try {
        const timeoutMs =
          isNip46Signer ? 4000 : 2000;
        console.warn(`${logPrefix} decrypt start`, {
          timeoutMs,
          signerType: wallet.ndk.signer?.constructor?.name ?? "unknown",
          isNip46Signer,
        });
        walletDecryptOk = await Promise.race([
          wallet.event.decrypt().then(() => true),
          new Promise<boolean>((resolve) => setTimeout(() => resolve(false), timeoutMs)),
        ]);
        console.warn(`${logPrefix} decrypt result`, {
          ok: walletDecryptOk,
          contentLength: typeof wallet.event.content === "string" ? wallet.event.content.length : 0,
        });
      } catch (error) {
        console.warn(`${logPrefix} decrypt error`, error);
        walletDecryptOk = false;
      }
      if (!walletDecryptOk) {
        console.warn(`${logPrefix} abort`, { reason: "wallet decrypt failed" });
        return;
      }
    }

    let deterministicInfo = decryptedDeterministicContent ?? '';

    // Try to have deterministic info ready for synchronous getter usage
    if (!deterministicInfo && deterministicInfoEvent) {
      const isNip46Signer = Boolean(
        wallet.ndk.signer?.constructor?.name?.includes("Nip46")
      );
      console.warn(`${logPrefix} deterministic info start`, {
        kind: deterministicInfoEvent.kind,
        pubkey: deterministicInfoEvent.pubkey,
        createdAt: deterministicInfoEvent.created_at ?? 0,
        contentLength:
          typeof deterministicInfoEvent.content === "string"
            ? deterministicInfoEvent.content.length
            : 0,
      });
      let deterministicDecryptOk = false;
      try {
        const timeoutMs =
          isNip46Signer ? 5000 : 2000;
        console.warn(`${logPrefix} deterministic decrypt start`, {
          timeoutMs,
          signerType: wallet.ndk.signer?.constructor?.name ?? "unknown",
          isNip46Signer,
        });
        const decrypted = await Promise.race([
          deterministicInfoEvent.decrypt().then(() => true),
          new Promise<boolean>((resolve) =>
            setTimeout(() => resolve(false), timeoutMs)
          ),
        ]);
        deterministicDecryptOk = Boolean(decrypted);
        console.warn(`${logPrefix} deterministic decrypt result`, {
          ok: deterministicDecryptOk,
          contentLength:
            typeof deterministicInfoEvent.content === "string"
              ? deterministicInfoEvent.content.length
              : 0,
        });
        deterministicInfo = deterministicInfoEvent.content;
      } catch (e) {
        console.warn("Error decrypting deterministic wallet event, skipping deterministic info.", e);
      }
    }

    // Initialize WalletState with counters snapshot parsed from deterministic info
    let countersSnapshot: Record<string, number> | undefined;
    let hasDeterministicInfo = false;

    if (deterministicInfo) {
      try {
        const infoContent = JSON.parse(deterministicInfo) as {
          bip39seed?: string;
          counters?: Record<string, number>;
        };

        if (typeof infoContent.bip39seed === "string") {
          wallet._bip39seed = hexToBytes(infoContent.bip39seed);
          if (isDeterministicCashuWalletInfoContent(infoContent)) {
            countersSnapshot = infoContent.counters;
          } else if (infoContent.counters && typeof infoContent.counters === "object") {
            countersSnapshot = infoContent.counters;
          } else {
            countersSnapshot = {};
          }
          hasDeterministicInfo = true;
          console.warn(`${logPrefix} deterministic info parsed`, {
            hasSeed: true,
            countersCount: countersSnapshot ? Object.keys(countersSnapshot).length : 0,
          });
        }
      } catch (e) {
        console.warn("Error parsing deterministic wallet info payload, skipping deterministic info.", e);
      }
    }

    if (hasDeterministicInfo) {
      wallet.state = new WalletState(wallet, new Set<string>(), countersSnapshot ?? {});
      console.warn(`${logPrefix} deterministic state applied`, {
        countersCount: countersSnapshot ? Object.keys(countersSnapshot).length : 0,
      });
    }

    try {
      console.warn(`${logPrefix} wallet content parse start`, {
        contentLength: typeof wallet.event.content === "string" ? wallet.event.content.length : 0,
      });
      const content = JSON.parse(wallet.event.content);
      let mintCount = 0;
      let privkeyCount = 0;
      for (const tag of content) {
        if (tag[0] === "mint") {
          wallet.mints.push(tag[1]);
          mintCount += 1;
        } else if (tag[0] === "privkey") {
          privkeyCount += 1;
          await wallet.addPrivkey(tag[1]);
        }
      }
      console.warn(`${logPrefix} wallet content parsed`, {
        mintCount,
        privkeyCount,
      });
    } catch (e) {
      console.warn(`${logPrefix} wallet content parse failed`, e);
      throw e;
    }

    console.warn(`${logPrefix} getP2pk start`, {
      existingP2pk: Boolean(wallet._p2pk),
      privkeyCount: wallet.privkeys.size,
    });
    await wallet.getP2pk();
    console.warn(`${logPrefix} getP2pk done`, {
      p2pk: wallet._p2pk ?? wallet.p2pk,
    });

    console.warn(`${logPrefix} done`, {
      kind: wallet.event.kind,
      pubkey: wallet.event.pubkey,
      mints: wallet.mints.length,
      privkeys: wallet.privkeys.size,
      hasDeterministicInfo: Boolean(wallet._bip39seed),
    });
    return wallet;
  }

  /**
   * Starts monitoring the wallet.
   *
   * Use `since` to start syncing state from a specific timestamp. This should be
   * used by storing at the app level a time in which we know we were able to communicate
   * with the relays, for example, by saving the time the wallet has emitted a "ready" event.
   */
  start(opts?: NDKSubscriptionOptions & { pubkey?: Hexpubkey; since?: number }) {
    if (this.status === NDKWalletStatus.READY) return;
    this.status = NDKWalletStatus.LOADING;

    const pubkey = opts?.pubkey ?? this.event?.pubkey;
    if (!pubkey) throw new Error("no pubkey");

    const filters: NDKFilter[] = [
      { kinds: [NDKKind.CashuToken], authors: [pubkey] },
      { kinds: [NDKKind.CashuQuote], authors: [pubkey] },
      {
        kinds: [NDKKind.EventDeletion],
        authors: [pubkey],
        "#k": [NDKKind.CashuToken.toString()],
      },
    ];

    if (opts?.since) {
      filters[0].since = opts.since;
      filters[1].since = opts.since;
    }

    opts ??= {};
    opts.subId ??= "cashu-wallet-state";
    opts.relaySet ??= this.relaySet;

    this.sub = this.ndk.subscribe(filters, opts, undefined, false);

    this.sub.on("event:dup", eventDupHandler.bind(this));
    this.sub.on("event", eventHandler.bind(this));
    this.sub.on("eose", () => {
      this.emit("ready");
      this.status = NDKWalletStatus.READY;
    });
    this.sub.start();
  }

  stop() {
    this.sub?.stop();
    this.status = NDKWalletStatus.INITIAL;
  }

  /**
   * Returns the p2pk of this wallet or generates a new one if we don't have one
   */
  async getP2pk(): Promise<string> {
    if (this._p2pk) return this._p2pk;

    if (this.privkeys.size === 0) {
      const signer = NDKPrivateKeySigner.generate();
      console.trace(`generating a new p2pk`, signer.privateKey);
      await this.addPrivkey(signer.privateKey!);
    }

    return this.p2pk;
  }

  /**
   * If this wallet has access to more than one privkey, this will return all of them.
   */
  get p2pks(): string[] {
    return Array.from(this.privkeys.keys());
  }

  async addPrivkey(privkey: string) {
    const signer = new NDKPrivateKeySigner(privkey);
    const user = await signer.user();
    this.privkeys.set(user.pubkey, signer);

    if (this.privkeys.size === 1) {
      this._p2pk = user.pubkey;
    }
  }

  set p2pk(pubkey: string) {
    if (this.privkeys.has(pubkey)) {
      this.signer = this.privkeys.get(pubkey);
      this.p2pk = pubkey;
    } else {
      throw new Error("privkey for " + pubkey + " not found");
    }
  }

  /**
   * Whether this wallet has been deleted
   */
  get isDeleted(): boolean {
    if (!this.event?.tags) return false;
    return this.event.tags.some((t) => t[0] === "deleted");
  }

  /**
   * Generates the payload for a wallet event
   */
  private walletPayload(): NDKTag[] {
    const privkeys = Array.from(this.privkeys.values().map((signer) => signer.privateKey!));

    return payloadForEvent(privkeys, this.mints);
  }

  async publish() {
    const logPrefix = "[wallet:publish]";
    if (!this.event) throw new Error("wallet event not available");
    const user = await this.ndk!.signer!.user();
    console.warn(`${logPrefix} start`, {
      pubkey: user.pubkey,
      mints: this.mints.length,
      privkeys: this.privkeys.size,
    });

    if (!this.isDeleted) {
      const payload = JSON.stringify(this.walletPayload());
      this.event.content = payload;
      await this.event.encrypt(user, undefined, "nip44");
      console.warn("[wallet:publish] wallet event encrypted");
    }

    this.event.pubkey = user.pubkey;
    this.event.created_at = Math.floor(Date.now() / 1000);
    await this.event.sign();
    console.warn("[wallet:publish] wallet event signed");
    const eventPromise = this.publishReplaceableWithTimeout(this.event, this.relaySet);
    let resultPromise;
    if (this._bip39seed) {
      const deterministicWalletPromise = this.publishDeterministicInfo(this.relaySet).catch((error) => {
        console.warn("[wallet] publishDeterministicInfo failed during publish", error);
        return new Set<NDKRelay>();
      });
      resultPromise = Promise.all([eventPromise, deterministicWalletPromise]).then(([walletRelays, deterministicRelays]) =>
        deterministicRelays.size > 0 ? walletRelays.intersection(deterministicRelays) : walletRelays
      );
    } else {
      resultPromise = eventPromise;
    }
    return resultPromise;
  }

  public async incrementDeterministicCounter(counterKey: string, counterIncrement: number, mergeCounters: boolean = true, tries: number = 3) {
    if (counterIncrement <= 0) return;

    tries--;
    try {
      const counter = this.state.getNextCounterByKey(counterKey);
      const nextCounter = (counter ?? 0) + counterIncrement;
      this.state.setNextCounterByKey(counterKey, nextCounter);
      await this.publishDeterministicInfo(this.relaySet, mergeCounters);
      console.log(`Published new counter ${nextCounter} for mint ${counterKey}`);
    } catch (e) {
      console.warn("[wallet] publishDeterministicInfo failed (mint transfer)!", e);
      if (tries >= 0) {
        console.log("Retrying ...");
        await this.incrementDeterministicCounter(counterKey, 0, mergeCounters, tries);
      }
      // If we can't publish event update the counter anyway to avoid secret collisions
      console.error("Giving up to publish deterministic info, but at least stored the last counter locally! Counter-Key: ", counterKey);
    }
  }

  /**
   * Publish Deterministic Cashu Wallet Info (kind 17376) as a replaceable event.
   * - Merges local counters with the latest remote snapshot using per-key max()
   * - Requires bip39seed to be set/derivable
   * - Encrypts content with NIP-44
   */
  private async publishDeterministicInfo(relaySet: NDKRelaySet | undefined = this.relaySet, mergeCounters: boolean = true): Promise<Set<NDKRelay>> {
    const seed = this._bip39seed;
    if (!seed) throw new Error("bip39seed not set");

    const user = await this.ndk!.signer!.user();

    // Local snapshot
    const localCounters = this.state.getDeterministicCountersSnapshot();
    let newCounters: Record<string, number> = { ...localCounters };

    if (mergeCounters) {
      // Merge with latest remote (per-key max)
      const latestRemote = await this.fetchLatestDeterministicInfoEvent(user.pubkey, relaySet);
      console.warn('latestRemote: ', latestRemote)

      if (latestRemote) {
        try {
          const decrypted = await this.withTimeout(
            latestRemote.decrypt().then(() => true),
            4000,
            "[wallet] Deterministic info decrypt"
          );
          if (decrypted) {
            const parsed = JSON.parse(latestRemote.content);
            if (isDeterministicCashuWalletInfoContent(parsed)) {
              newCounters = this.mergeCountersMax(newCounters, parsed.counters ?? {});
            }
            console.warn("[wallet:publish] deterministic info decrypted");
          }
        } catch {
          // ignore decrypt/parse errors and keep local snapshot
        }
      }

      // Ensure internal state doesn't regress vs merged snapshot
      for (const [k, v] of Object.entries(newCounters)) {
        try {
          this.state.setNextCounterByKey(k, v);
        } catch {
          // ignore invalid key formats
        }
      }
    }

    // Build and publish replaceable deterministic info event
    const info = new NDKEvent(this.ndk);
    info.kind = DeterministicCashuWalletInfoKind;
    info.tags = [];
    info.content = JSON.stringify({
      bip39seed: bytesToHex(seed),
      counters: newCounters,
    });


    await info.encrypt(user, undefined, "nip44");

    let infoContentLength = info.content?.length ?? 0;
    console.warn('[wallet:publish] deterministic encrypted', {
      scheme: 'nip44',
      contentLength: infoContentLength,
    });

    info.pubkey = user.pubkey;
    info.created_at = Math.floor(Date.now() / 1000);
    await info.sign();
    console.warn('info event SIGNED, publishing. relayset:', relaySet)
    const relays = await this.publishReplaceableWithTimeout(info, relaySet);
    console.warn('info event published. SUCCESS')

    return relays;
  }

  /**
   * Fetch the latest Deterministic Cashu Wallet Info event (kind 17376) for a pubkey.
   * Uses max(created_at) to select the latest without relying on sort order.
   */
  private async fetchLatestDeterministicInfoEvent(
    pubkey: string,
    relaySet?: NDKRelaySet,
    timeoutMs = 3000
  ): Promise<NDKEvent | undefined> {
    const filter: NDKFilter = {
      kinds: [DeterministicCashuWalletInfoKind],
      authors: [pubkey],
      limit: 1,
    };

    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<null>((resolve) => {
      timeoutId = setTimeout(() => resolve(null), timeoutMs);
    });

    const set = await Promise.race([
      this.ndk.fetchEvents(filter, {
        cacheUsage: NDKSubscriptionCacheUsage.ONLY_RELAY,
        relaySet,
      }),
      timeoutPromise,
    ]);

    if (timeoutId) clearTimeout(timeoutId);
    if (!set) {
      console.warn(
        `[wallet] Timed out fetching deterministic info after ${timeoutMs}ms`,
        { pubkey }
      );
      return undefined;
    }
    if (set.size === 0) return undefined;

    const list = Array.from(set.values());
    let latest: NDKEvent | undefined = undefined;
    for (const ev of list) {
      if (!latest || (ev.created_at ?? 0) > (latest.created_at ?? 0)) {
        latest = ev;
      }
    }
    return latest;
  }

  /**
   * Merge counters using per-key max semantics.
   */
  private mergeCountersMax(
    a: Record<string, number>,
    b: Record<string, number>
  ): Record<string, number> {
    const out: Record<string, number> = { ...a };
    for (const [k, v] of Object.entries(b)) {
      const lv = out[k] ?? 0;
      const nv = Number.isInteger(v) && v >= 0 ? v : 0;
      out[k] = Math.max(lv, nv);
    }
    return out;
  }

  /**
   * Prepares a deposit
   * @param amount
   * @param mint
   *
   * @example
   * const wallet = new NDKCashuWallet(...);
   * const deposit = wallet.deposit(1000, "https://mint.example.com", "sats");
   * deposit.on("success", (token) => {
   *   console.log("deposit successful", token);
   * });
   * deposit.on("error", (error) => {
   *   console.log("deposit failed", error);
   * });
   *
   * // start monitoring the deposit
   * deposit.start();
   */
  public deposit(amount: number, mint?: string): NDKCashuDeposit {
    const deposit = new NDKCashuDeposit(this, amount, mint);
    deposit.on("success", (token) => {
      this.state.addToken(token);
    });
    return deposit;
  }

  /**
   * Receives a token and adds it to the wallet
   * @param token
   * @returns the token event that was created
   */
  public async receiveToken(token: string, description?: string) {
    let { mint } = getDecodedToken(token);
    const wallet = await this.getCashuWallet(mint, this._bip39seed);
    const currentCounterEntry = await this.state.getCounterEntryFor(wallet.mint);
    const counter = this._bip39seed ? currentCounterEntry.counter ?? 0 : undefined;
    const proofs = await wallet.receive(token, { counter });

    const updateRes = await this.state.update({
      store: proofs,
      mint,
    });
    const tokenEvent = updateRes.created;

    if (this._bip39seed && proofs.length) {
      // Increment deterministic counters by number of newly received proofs (active keyset)
      await this.incrementDeterministicCounter(currentCounterEntry.counterKey, proofs.length);
    }

    createInTxEvent(this.ndk, proofs, mint, updateRes, { description }, this.relaySet);

    return tokenEvent;
  }

  /**
   * Pay a LN invoice with this wallet
   */
  async lnPay(
    payment: PaymentWithOptionalZapInfo<LnPaymentInfo>,
    createTxEvent = true
  ): Promise<NDKPaymentConfirmationLN | undefined> {
    return this.paymentHandler.lnPay(payment, createTxEvent);
  }

  /**
   * Swaps tokens to a specific amount, optionally locking to a p2pk.
   *
   * This function has side effects:
   * - It swaps tokens at the mint
   * - It updates the wallet state (deletes affected tokens, might create new ones)
   * - It creates a wallet transaction event
   *
   * This function returns the proofs that need to be sent to the recipient.
   * @param amount
   */
  async cashuPay(
    payment: NDKZapDetails<CashuPaymentInfo>
  ): Promise<NDKPaymentConfirmationCashu | undefined> {
    return this.paymentHandler.cashuPay(payment);
  }

  public wallets = new Map<string, CashuWallet>();

  async redeemNutzaps(
    nutzaps: NDKNutzap[],
    privkey: string,
    { mint, proofs, cashuWallet }: RedeemNutzapsOpts
  ): Promise<number> {
    if (cashuWallet) {
      mint ??= cashuWallet.mint.mintUrl;
    } else {
      if (!mint) throw new Error("mint not set");
      cashuWallet = await this.getCashuWallet(mint, this._bip39seed);
    }

    if (!mint) throw new Error("mint not set");
    if (!proofs) throw new Error("proofs not set");

    try {
      const proofsWeHave = this.state.getProofs({ mint });
      const currentCounterEntry = await this.state.getCounterEntryFor(cashuWallet.mint);
      const counter = this._bip39seed ? currentCounterEntry.counter ?? 0 : undefined;
      const res = await cashuWallet.receive({ proofs, mint }, { proofsWeHave, privkey, counter });

      if (this._bip39seed && res.length) {
        await this.incrementDeterministicCounter(currentCounterEntry.counterKey, res.length);
      }

      const receivedAmount = proofs.reduce((acc, proof) => acc + proof.amount, 0);
      const redeemedAmount = res.reduce((acc, proof) => acc + proof.amount, 0);
      const fee = receivedAmount - redeemedAmount;

      const updateRes = await this.state.update({
        store: res,
        mint,
      });

      createInTxEvent(this.ndk, res, mint, updateRes, { nutzaps, fee }, this.relaySet);

      return receivedAmount;
    } catch (e) {
      console.log(
        "error redeeming nutzaps",
        nutzaps.map((n) => n.encode()),
        e
      );
      console.trace(e);
      throw e;
    }
  }

  /**
   * Recovers funds (Cashu proofs) from the deterministic wallet defined by the given BIP-39 seed and mint. In case the given seed is 
   * different to the one of this wallet, the restored proofs get spendable in this wallet, but not backed up by this wallet's seed.
   * 
   * @param bip39seed the seed to restore from
   * @param mint the mint to be used, it must be a mint of this wallet. The method throws an error otherwise.
   * @param options object containing options to customize the restore process.
   *  - @param gapLimit The amount of empty counters that should be returned before restoring ends (defaults to 300). Default is 300
   *  - @param batchSize The amount of proofs that should be restored at a time (defaults to 100). Default is 100
   *  - @param startCounter The counter that should be used as a starting point (defaults to 0). Default is 0
   *  - @param activeKeysets If true only active keysets will be restored. Default is false.
   * @returns An object with the errors, if any, and the RecoverResult containing unspent and spent recovered proofs, if any were recovered.
   */
  public async recoverProofsFromSeed(bip39seed: Uint8Array, mint: string, options: RestoreWalletOpts = {})
    : Promise<{ errors: any[], recoverResult: RecoverResult }> {
    if (!this.mints.includes(mint)) throw new Error("Recovering a wallet is only available for mints of this wallet");

    const { gapLimit, batchSize, startCounter, activeKeysets } = options;
    var cashuWallet;
    try {
      // restoring this wallet
      if (bip39seed === this._bip39seed) {
        cashuWallet = await this.getCashuWallet(mint, bip39seed);
      } else { // use an ephemeral cashu wallet to restore a different wallet
        cashuWallet = await walletForMint(mint, {
          bip39seed: bip39seed,
          onMintInfoNeeded: this.onMintInfoNeeded,
          onMintInfoLoaded: this.onMintInfoLoaded,
          onMintKeysNeeded: this.onMintKeysNeeded,
          onMintKeysLoaded: this.onMintKeysLoaded
        });
      }
    } catch (e) {
      console.error(`Error ${e} loading wallet for mint: ${mint}`);
    }
    if (!cashuWallet) {
      throw new Error(`Couldn't load wallet for mint: ${mint}. Continue with next mint...`);
    }

    let resultProofs: Proof[] = [];
    let aggregatedErrors = [];
    const mintKeysets = await cashuWallet.mint.getKeySets();
    const keysets = activeKeysets ? mintKeysets.keysets.filter(ks => ks.active) : mintKeysets.keysets;
    for (const keyset of keysets) {
      try {
        const { proofs, lastCounterWithSignature } = await cashuWallet.batchRestore(gapLimit, batchSize, startCounter, keyset.id);
        if (proofs.length) {
          await this.state.update(
            {
              mint: mint,
              store: proofs
            },
            "Restored");
          resultProofs = resultProofs.concat(proofs);
        }
        try {
          // when restoring this wallet update counters if needed
          if (bip39seed === this._bip39seed && proofs.length) {
            const counterEntry = await this.state.getCounterEntryFor(cashuWallet.mint);
            const currentCounter = counterEntry.counter ?? 0;
            const counterIncrement = lastCounterWithSignature && lastCounterWithSignature + 1 > currentCounter ?
              lastCounterWithSignature - currentCounter + 1 : 0;
            this.incrementDeterministicCounter(counterEntry.counterKey, counterIncrement);
          }
        } catch (e) {
          console.error(`Error ${e} updating counter state in relays after restore for mint ${mint} and keyset ${keyset.id}. Continue with next keyset...`);
          aggregatedErrors.push(e);
        }
      } catch (e) {
        console.error(`Error ${e} restoring proofs for mint ${mint} and keyset ${keyset.id}. Continue with next keyset...`);
        aggregatedErrors.push(e);
      }
    }
    let recoverResult = {};
    if (resultProofs.length) {
      // Proofs received from mint can be already spent. Consolidate and update wallet state.
      try {
        const consolidationResult = await consolidateMintTokens(mint, this, resultProofs);
        if (!consolidationResult) {
          recoverResult = {
            unspent: resultProofs
          }
        } else {
          recoverResult = {
            unspent: consolidationResult.created?.proofs.concat(consolidationResult.reserved?.proofs ?? []),
            spent: consolidationResult.deleted
          }
        }
      } catch (e) {
        console.error(`Error ${e} consolidating proofs for mint ${mint}, some restored proofs maybe already spent.`);
        aggregatedErrors.push(e);
      }
    }

    return { errors: aggregatedErrors, recoverResult };
  }

  public warn(msg: string, event?: NDKEvent, relays?: NDKRelay[]) {
    relays ??= event?.onRelays;
    this.warnings.push({ msg, event, relays });
    this.emit("warning", { msg, event, relays });
  }

  get balance(): NDKWalletBalance | undefined {
    return {
      amount: this.state.getBalance({ onlyAvailable: true }),
    };
  }

  /**
   * Gets the total balance for a specific mint, including reserved proofs
   */
  public mintBalance(mint: MintUrl): number {
    return this.mintBalances[mint] || 0;
  }

  /**
   * Gets all tokens, grouped by mint with their total balances
   */
  get mintBalances(): Record<MintUrl, number> {
    return this.state.getMintsBalance({ onlyAvailable: true });
  }

  /**
   * Returns a list of mints that have enough available balance (excluding reserved proofs)
   * to cover the specified amount
   */
  getMintsWithBalance(amount: number): MintUrl[] {
    const availableBalances = this.state.getMintsBalance({ onlyAvailable: true });
    return Object.entries(availableBalances)
      .filter(([_, balance]) => balance >= amount)
      .map(([mint]) => mint);
  }
}

export class NDKCashuWalletBackup extends NDKEvent {
  public privkeys: string[] = [];
  public mints: string[] = [];

  constructor(ndk: NDK, event?: NDKEvent) {
    super(ndk, event);
    this.kind ??= NDKKind.CashuWalletBackup;
  }

  static async from(event: NDKEvent): Promise<NDKCashuWalletBackup | undefined> {
    if (!event.ndk) throw new Error("no ndk instance on event");

    const backup = new NDKCashuWalletBackup(event.ndk, event);

    try {
      await backup.decrypt();
      const content = JSON.parse(backup.content);
      for (const tag of content) {
        if (tag[0] === "mint") {
          backup.mints.push(tag[1]);
        } else if (tag[0] === "privkey") {
          backup.privkeys.push(tag[1]);
        }
      }
    } catch (e) {
      console.log("error decrypting backup event", backup.encode(), e);
      return;
    }

    return backup;
  }

  async save(relaySet?: NDKRelaySet) {
    if (!this.ndk) throw new Error("no ndk instance");
    if (!this.privkeys.length) throw new Error("no privkeys");
    this.content = JSON.stringify(payloadForEvent(this.privkeys, this.mints));
    await this.encrypt(this.ndk.activeUser!, undefined, "nip44");
    return this.publish(relaySet);
  }
}

function payloadForEvent(privkeys: string[], mints: string[]) {
  if (privkeys.length === 0) throw new Error("privkey not set");

  const payload: NDKTag[] = [
    ...mints.map((mint) => ["mint", mint]),
    ...privkeys.map((privkey) => ["privkey", privkey]),
  ];

  return payload;
}
