# -*- coding: utf-8 -*-
import re
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_darkmarket(SpiderFootPlugin):

    meta = {
        'name': "DarkMarket Analyzer",
        'summary': "Extrahiert technische Identifikationsmerkmale aus Darknet-Marktplätzen.",
        'useCases': ["Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {}
    optdescs = {}

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        # Korrelationsspeicher: Merkmal -> Liste der Seiten
        self.seen = dict()
        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT"]

    def producedEvents(self):
        return ["PGP_KEY", "BITCOIN_ADDRESS", "XMR_ADDRESS", "EMAILADDR",
                "USERNAME", "ACCOUNT_EXTERNAL_OWNED", "DATE"]

    def correlate(self, identifier, source_url, event):
        # Erstes Auftreten dieses Merkmals: nur speichern
        if identifier not in self.seen:
            self.seen[identifier] = [source_url]
            return

        # Bereits gesehen: Korrelation, falls andere Seite
        if source_url not in self.seen[identifier]:
            self.seen[identifier].append(source_url)
            seiten = ", ".join(self.seen[identifier])
            meldung = f"Korrelation: {identifier} erscheint auf {seiten}"
            self.info(meldung)
            evt = SpiderFootEvent("RAW_RIR_DATA", meldung, self.__name__, event)
            self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        source_url = event.actualSource if event.actualSource else "unbekannt"

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # 1. Oeffentliche PGP-Schluessel
        pgp_pattern = r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----"
        for key in set(re.findall(pgp_pattern, eventData, re.DOTALL)):
            self.info("PGP-Schluessel gefunden")
            evt = SpiderFootEvent("PGP_KEY", key, self.__name__, event)
            self.notifyListeners(evt)
            self.correlate(key, source_url, event)

        # 2. Bitcoin-Adressen
        btc_pattern = r"\b(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
        for addr in set(re.findall(btc_pattern, eventData)):
            self.info(f"Bitcoin-Adresse gefunden: {addr}")
            evt = SpiderFootEvent("BITCOIN_ADDRESS", addr, self.__name__, event)
            self.notifyListeners(evt)
            self.correlate(addr, source_url, event)

        # 3. Monero-Adressen
        xmr_pattern = r"\b4[0-9AB][a-zA-Z0-9]{93}\b"
        for addr in set(re.findall(xmr_pattern, eventData)):
            self.info(f"Monero-Adresse gefunden: {addr}")
            evt = SpiderFootEvent("XMR_ADDRESS", addr, self.__name__, event)
            self.notifyListeners(evt)
            self.correlate(addr, source_url, event)

        # 4. E-Mail-Adressen
        email_pattern = r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
        for addr in set(re.findall(email_pattern, eventData)):
            self.info(f"E-Mail-Adresse gefunden: {addr}")
            evt = SpiderFootEvent("EMAILADDR", addr, self.__name__, event)
            self.notifyListeners(evt)
            self.correlate(addr, source_url, event)

        # 5. Benutzernamen (nach Etikett wie Verkäufer:, Vendor:, usw.)
        user_pattern = r"(?:Verkäufer|Vendor|Username|User|Seller)\s*:\s*([A-Za-z0-9_.-]+)"
        for name in set(re.findall(user_pattern, eventData)):
            self.info(f"Benutzername gefunden: {name}")
            evt = SpiderFootEvent("USERNAME", name, self.__name__, event)
            self.notifyListeners(evt)
            self.correlate(name, source_url, event)

        # 6. Kontaktinformationen (Telegram, Jabber, usw.)
        kontakt_pattern = r"(?:Telegram|Jabber|XMPP|Session|Signal|Wickr)\s*:\s*(@?[A-Za-z0-9_.@-]+)"
        for kontakt in set(re.findall(kontakt_pattern, eventData)):
            self.info(f"Kontakt gefunden: {kontakt}")
            evt = SpiderFootEvent("ACCOUNT_EXTERNAL_OWNED", kontakt, self.__name__, event)
            self.notifyListeners(evt)
            self.correlate(kontakt, source_url, event)

        # 7. Zeitstempel (werden extrahiert, aber NICHT korreliert)
        datum_pattern = r"\b(\d{2}\.\d{2}\.\d{4}|\d{4}-\d{2}-\d{2})\b"
        for datum in set(re.findall(datum_pattern, eventData)):
            self.info(f"Zeitstempel gefunden: {datum}")
            evt = SpiderFootEvent("DATE", datum, self.__name__, event)
            self.notifyListeners(evt)
