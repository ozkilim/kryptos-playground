# Weltzeituhr (Alexanderplatz) as it looked in 1989: research note

Data: `data/weltzeituhr_1989.json`. Compiled 2026-11-15.

## Bottom line

- **There is now a partial, photo-verified pre-1997 transcription.** The key find is the Commons photo
  [Berlin_Alexanderplatz_Kaufhof.jpg](https://commons.wikimedia.org/wiki/File:Berlin_Alexanderplatz_Kaufhof.jpg)
  (caption "1991", uploaded 2022 as own work). It shows **LENINGRAD, GORKI, SWERDLOWSK, ALMA-ATA, TBILISSI, DACCA**,
  so it predates the Oct–Dec 1997 renovation. It covers UTC 0 … +7 on both plates. (nitsuah/kryptos flagged it as
  possibly showing PRESSBURG/KAPSTADT. At pixel level it does not: the plates read BRAZZAVILLE/KINSHASA/LUANDA and
  KHARTUM/LUSAKA/MAPUTO.)
- **7 of 24 facets have complete c.1989–91 lists:** UTC 0, +1, +2, +3, +4, +5, +6. On +3 the 9th bottom line is illegible.
- **+7 … +12:** the upper plates are verified from Bundesarchiv photos (Apr 1984, 30 Aug 1989). The lower plates are unknown or only partly read.
- **−11 … −1:** no usable photo from after 1980. The best available readings are from 1971 and c.1978, and these plates
  *did* change between 1970, 1978, 1980 and 1991. These facets are marked reconstructed or post-1997 only.
- **About 80 of an estimated ~130 pre-1997 names are directly verified.** The post-1997 list (146 names plus a DATUMSGRENZE entry) is complete
  ([official site](http://www.weltzeituhr-berlin.de/en/places-worldtimeclock), [hu-wiki facet grouping](https://hu.wikipedia.org/wiki/Ur%C3%A1nia_vil%C3%A1g%C3%B3ra),
  [2017 photo transcription](https://github.com/zeyeteam-debug/kryptos-k4-eliminations)).

## c.1989–91 plates (verified part)

Each facet lists the upper plate, then `||`, then the lower plate. Names are read top to bottom, in the plate spelling.

| UTC | upper | lower |
|---|---|---|
| 0 | REYKJAVIK DUBLIN LONDON LISSABON ALGIER MADEIRA BISSAU | CASABLANCA CONAKRY DAKAR BAMAKO ACCRA |
| +1 | AMSTERDAM BERLIN BRÜSSEL BUDAPEST MADRID PARIS PRAG STOCKHOLM WARSCHAU | KOPENHAGEN WIEN BERN BELGRAD ROM TUNIS BRAZZAVILLE KINSHASA LUANDA |
| +2 | BUKAREST HELSINKI SOFIA ATHEN NIKOSIA | BEIRUT DAMASKUS KAIRO · KHARTUM LUSAKA MAPUTO(?) |
| +3 | MURMANSK LENINGRAD MOSKAU KIEW | ANKARA TEHERAN+ BAGDAD ADEN SANÁ ADDIS ABEBA MOGADISCHU DARESSALAM [illegible] |
| +4 | GORKI WOLGOGRAD BAKU TBILISSI JEREWAN | KABUL+ (+30') |
| +5 | SWERDLOWSK ASCHCHABAD | DELHI+ KARACHI COLOMBO+ MAURITIUS (+30') |
| +6 | OMSK ALMA-ATA TASCHKENT | RANGUN+ DACCA (+30') |
| +7 | KRASNOJARSK NOWOSIBIRSK | 5 lines, illegible (1984 shows BANGKOK) |
| +8 | IRKUTSK ULAN BATOR | PEKING SHANGHAI … |
| +9 | JAKUTSK | PHOENGJANG … |
| +10 | CHABAROWSK WLADIWOSTOK (1984; the Aug 1989 photo shows only CHABAROWSK) | ? |
| +11 | MAGADAN SACHALIN (Aug 1989) | ? |
| +12 | KAMTSCHATKA (Aug 1989) | ? |

The Apr 1984 and 15 Jul 1980 Bundesarchiv photos agree with the c.1991 photo wherever they overlap.

## Notable differences from the post-1997 clock (relevant to key-stream experiments)

- **Renamed:** LENINGRAD→ST. PETERSBURG, ALMA-ATA→ALMATY, GORKI→NISCHNIJ NOWGOROD, SWERDLOWSK→JEKATERINBURG,
  TBILISSI→TIFLIS, JEREWAN→ERIWAN, ASCHCHABAD→ASCHGABAT, DELHI→NEW DELHI, DACCA→DHAKA, SANÁ→SANAA,
  PHOENGJANG→PJÖNGJANG.
- **Moved:** KIEW +3→+2, ANKARA +3→+2, ATHEN from the +2 upper plate to the lower, MAURITIUS +5→+4, NOWOSIBIRSK +7→+6.
- **Removed in 1997:** ALGIER, BRAZZAVILLE, LUANDA, KHARTUM, LUSAKA, MAPUTO.
- **Added in 1997:** 20 in total ([BZ 12.12.1997](https://www.berliner-zeitung.de/20-staedtenamen-wurden-bei-der-restaurierung-ergaenzt-frisch-poliert-die-weltzeituhr-dreht-sich-bald-li.7079),
  [taz 20.12.1997](https://taz.de/!1367509/)). The photos show these on the verified facets: OSLO, PRESSBURG, RIGA, TALLINN, WILNA, MINSK, ISTANBUL, TEL AVIV,
  JERUSALEM, KAPSTADT, KUWAIT, BISCHKEK, DUSCHANBE. SEOUL is documented as a 1997 addition but sits on an unread facet.
  The other ~6 additions are probably on the unread western and lower facets (candidates: BRASILIA, MANAGUA, LOS ANGELES, APIA).
- **No BRATISLAVA appears on either +1 plate in c.1991.** The "Bratislava renamed to Pressburg" line on de-wiki looks like a new
  PRESSBURG plate entry, not a rename.

## Reliability

- **High:** the +1 upper plate and the 1980/1984/1989 Bundesarchiv readings. These are clear, dated archive photos.
- **Medium-high:** the c.1991 Kaufhof photo. It is a 1417 px scan read at 5–8× zoom. Most lines are clear. MAPUTO, the 9th line of +3 and
  the +7 lower plate are blurred. Its exact date is uncertain: the caption says 1991, Kaufhof took over Centrum in 1991, and
  the legacy names prove it predates 1997. I assume nothing changed between Nov 1989 and that photo, since no works are
  documented before Oct 1997.
- **Low:** the readings of the west side (−11 … −1). They are 1971/1978 states. The 1983 Alaska time-zone change and the reported 1985 maintenance
  ([Tagesspiegel 2019](https://www.tagesspiegel.de/berlin/die-weltzeituhr-kennt-jeder-niemand-ihren-erfinder-6541270.html), paywalled, via the
  [nitsuah audit](https://github.com/nitsuah/kryptos/blob/main/docs/analysis/K4_WORLD_CLOCK_HISTORICAL_SOURCES.md))
  probably changed these plates. Between 1980 and 1991, for example, REYKJAVIK/MADEIRA moved from −1 to 0 and LONDON moved from the +1 lower plate to 0.
- **The 1970 layout is not the 1989 layout.** It had about 80 names, with LONDON on +1 (the British Standard Time era) and no ATHEN. Do not use
  1970 photos as a stand-in for 1989.

## Orientation (which facet faces ENE)

No source documents it. A rough estimate from photographs taken toward known landmarks (the Fernsehturm is WSW of the
clock, the Kaufhof is N/NNE) puts the Berlin (+1) facet facing roughly S–SW. UTC increases counter-clockwise seen from
above, about −15° of bearing per hour. On that basis the **ENE-facing facet is among +8 … +12**, most likely +10 or +11
(CHABAROWSK/WLADIWOSTOK or MAGADAN/SACHALIN). The uncertainty is ±2 facets. To pin it down, take a compass bearing on site or a georeferenced photo; the pavement
compass rose is the obvious reference.

## Other features

- **Planetary model:** a simplified solar system of spheres on steel rings that rotates once a minute. A ringed Saturn is visible in photos.
- **Hour ring:** numerals 1–24 in colour-coded frames.
- **Column:** 2.7 m high, tiled with a world map, carrying 4 small clocks.
- **Pavement:** a stone-mosaic compass rose.
- **Inscriptions:** no base inscription text was found anywhere. The only text elements are city names, "+30'" marks and DATUMSGRENZE.
- **Counts conflict between sources:** 80 original names (official site), 97 (Erich John, B.Z. 2019), 146/147/148 now.

## Gaps and next steps

1. Find a sharp 1985–1997 photo of the west side (UTC −11 … −1) and of the lower plates for +7 … +12. Candidates:
   - AKG Images 668482 (Pansegrau, c.1986/90, 5k px)
   - Verein für die Geschichte Berlins Mi-A 245 (1980s slide)
   - Getty/ullstein 957270880 (1990)
   - the Bundesarchiv originals at full resolution
2. Get the original 1417 px Kaufhof scan's source negative or a higher-resolution version to resolve MAPUTO, the 9th line of +3 and the +7 lower plate. The uploader is Mabit1.
3. Kunsch Metallbau reportedly holds the 1969 drawings and lettering samples (B.Z. 23.11.2024, per the nitsuah audit).
4. Measure the facet bearings on site.

## Photo sources used

- [Fortepan 60040 (summer 1970)](https://commons.wikimedia.org/wiki/File:Kelet-Berlin,_Alexanderplatz._Fortepan_60040.jpg)
- [Fortepan 61101 (1971)](https://commons.wikimedia.org/wiki/File:Kelet-Berlin,_Alexanderplatz,_el%C5%91t%C3%A9rben_a_vil%C3%A1g%C3%B3ra,_balra_a_Haus_des_Lehrers._Fortepan_61101.jpg)
- [Fortepan 73787 (c.1978)](https://commons.wikimedia.org/wiki/File:Kelet-Berlin,_Alexanderplatz,_a_vil%C3%A1g%C3%B3ra._Fortepan_73787.jpg)
- [Blobelt (31 Jan 1970)](https://commons.wikimedia.org/wiki/File:19700131040NR_Berlin_Weltzeituhr_am_Alexanderplatz.jpg)
- [BArch 183-W0715-0026 (15 Jul 1980)](https://commons.wikimedia.org/wiki/File:Bundesarchiv_Bild_183-W0715-0026,_Berlin,_Alexanderplatz,_Weltzeituhr.jpg)
- [BArch 183-1984-1419-014 (Apr 1984)](https://commons.wikimedia.org/wiki/File:Bundesarchiv_Bild_183-1984-1419-014,_Berlin,_Weltzeituhr_am_Alexanderplatz.jpg)
- [BArch 183-1989-0830-028 (30 Aug 1989)](https://commons.wikimedia.org/wiki/File:Bundesarchiv_Bild_183-1989-0830-028,_Berlin,_Fernsehturm,_Weltzeituhr.jpg)
- [Kaufhof (c.1991)](https://commons.wikimedia.org/wiki/File:Berlin_Alexanderplatz_Kaufhof.jpg)

Other sources: [de-wiki](https://de.wikipedia.org/wiki/Weltzeituhr_(Alexanderplatz)), [en-wiki](https://en.wikipedia.org/wiki/World_Clock_(Alexanderplatz)),
[official history](https://www.weltzeituhr-berlin.de/en/urania-worldtimeclock), [BZ Pressburg 20.12.1997](https://www.berliner-zeitung.de/15998478).
