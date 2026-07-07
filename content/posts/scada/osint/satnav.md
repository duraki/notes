---
title: "SATNav 🛰️"
url: '/osint/satnav'
---

The SATNAV (or _Satellite Navigation_) refers to systems that provide positioning, navigation, and timing (PNT) information using satellites (mostly GPS, but also GLONASS, Galileo, BeiDou, and regional/augmentntation) systems.

For [OSINT](/osint), and [SCADA](/scada) security, satnav data and infrastructure are valuable since they are a source of open ifnromation (ie. _tracks_, _timing_) and also an attack surface (ie. _jamming_, _spoofing_, _misconfiguration_) that can affect critical systems.

This note covers what satnav is and the major constellations, public data sources and OSINT techniques, commong tools and formats, and security considerations relevant to ICS and/or SCADA systems.

{{< imgcap title="Euroscope Emulator for SatNAV OffSec Training & Research" src="/posts/images/EuroScope_at_Dublin.png" >}}

### Airspace

Airspace over Bosnia and Herzegovina is managed by the **VATAdria** facility under the VATSIM region.

To become an air traffic controller in this region:
{{< notice >}}
Step 1: Register controller account using VATSIM Membership
{{< /notice >}}
{{< callout emoji="👤" text="Sign up as a controller on the [VATSIM Membership](https://vatsim.net/docs/basics/join-vatsim/) portal and choose the Europe, Middle East and Africa (_see:_ [EMEA](https://vatsim.net/docs/regions/emea) VATSIM documents) region." >}}

{{< notice >}}
Step 2: Get Trained on ATC
{{< /notice >}}
{{< callout emoji="✈️" text="ATC training and mentoring are managed by the division. Connect with the regional community via the [VATAdria website](https://vatadria.com/) to start your training." >}}

{{< notice >}}
Step 3: Learn Controller' Procedures
{{< /notice >}}
{{< callout emoji="📚" text="Familiarize yourself with the local sectors, charts, and regional differences before taking the scope." >}}

* **Do the above requirements:** Register account, Get Trained, Learn Procedures
* _... then read further instructions on VATSIM wiki pages below..._
* ---
* VATSIM Docs: [Becoming A Controller](https://vatsim.net/docs/basics/becoming-a-controller)
* VATSIM Docs: [Regions](https://vatsim.net/docs/regions/regions)
* VATEUD Web: [European VATSIM Division](https://core.vateud.net)
* VATSIM Web: [International VATSIM Network](https://vatsim.net), on Reddit [/r/vatsim](https://old.reddit.com/r/VATSIM/), on [Wiki](https://en.wikipedia.org/wiki/Virtual_Air_Traffic_Simulation_Network)

### Systems & Sgnals

- `GPS` (USA 🇺🇸) — L1/L2/L5 frequencies, civilian L1 C/A.
- `GLONASS` (Russia 🇷🇺) — frequency-division multiplexing.
- `Galileo` (EU 🇪🇺) — E1, E5a/b, E6.
- `BeiDou` (China 🇨🇳) — multiple signals and regional services.
- `SBAS` / _augmentation systems_ (e.g., `WAAS`, `EGNOS`) — improve accuracy for aviation and other uses.
- `RTK` (Real-Time Kinematic) / `CORS` _networks_ — centimeter-level positioning using corrections.

GNSS receivers output standard formats like NMEA (plain text sentences), and higher-precision logs use RINEX, RTCM, or proprietary vendor formats.

### Public [OSINT](/osint) Data Sources (`@~> ` at `SATNAV`)

- **Flight trackers:** OpenSky Network, Flightradar24, ADS-B Exchange, FlightAware — useful for aircraft tracks and timestamps.
- **Marine trackers:** AIS aggregators (MarineTraffic, Vesselfinder) — vessel positions and movement history.
- **Public GNSS correction/CORS servers:** national CORS, IGS (International GNSS Service) — raw observation data and station logs.
- **Crowd-sourced route services:** Strava (if public), Garmin Connect (if public), GPX files on GitHub or public forums.
- **Imagery & metadata:** geotagged photos, EXIF data, Google Maps/Earth historical imagery.
- **Radio/Satellite monitoring forums:** `rtl-sdr` forums, _GNSS_ monitoring projects that publish anomalies.
- **Regulatory / Civil Sources:** NOTAMs (for aviation), AIS / port authority logs.
- **Social media & field reports:** posts with screenshots, coordinates, or embedded maps.

### Common File Formats / Protocols

- `NMEA 0183` — single-line text sentences _(GGA, RMC, VTG, etc.)_, easy to parse.
- `GPX / KML` — exchange formats for tracks and waypoints.
- `RINEX` — standard for raw GNSS observation data _(used in research/CORS)_.
- `RTCM` — differential correction formats used by `RTK/CORS`.
- `ADS‑B` (Mode S) via `dump1090/SDR` — aircraft position messages.
- `AIS` _(sentence formats)_ — vessel dynamic/static information.

### Tools

Tools that read/convert these: `exiftool`, `gpsbabel`, `gpsd`, `pyproj`, `GDAL/OGR` (for geospatial conversions), `QGIS` for visualization.

**Example:** extract GPS coordinates from a photo:

```bash
$ exiftool -gpslatitude -gpslongitude image.jpg
```

**Example:** Convert GPX to GeoJSON for quick web viewing:

```bash
$ gpsbabel -i gpx -f track.gpx -o geojson -F track.geojson
```

### Software Systems & Solutions

**EuroSpace**

EuroScope is an advanced, specialized Radar and Air Traffic Control (ATC) simulation software designed primarily for the VATSIM Network. See also [dark gray](https://github.com/judemille/GrayEuroScope) plugin.

It features a highly customizable, multi-window interface that replicates real-world controller workstations. This includes a primary radar screen, flight data lists, communications menus, and weather toolbars.

You can download the latest installer directly from the [EuroScope Downloads](https://www.euroscope.hu/) page or reading the [official documentation](https://www.euroscope.hu/wp/installation/). Yuu might need a specifal [EuroScope Sector](EuroScope Sector File Provider File) file provider. This default provider contains an initial list of sector file providers. After downloading it, the descriptor file will contain all these entries. Each of these entries represents a sector file provider and the web address, where its so-called provider file can be found. Such a provider file contains two groups of entries: _links to neighboring or subordinate providers_, and _links to sector files that this provider offers_. For Linux-based systems, opt-in for an Euroscope over Wine, available [here](https://appdb.winehq.org/objectManager.php?sClass=application&iId=9470).

**VATSIM**

[VATSIM](https://github.com/vatsimnetwork) is a virtual ATC network, and it hosts a virtual air traffic control services and public traffic/state data. Regional facilities provide ATC coverage and event logs depending on the country. These networks can be useful OSINT sources for aircraft call signs, routes, timestamps, and controller reports, especially when used to cross-check ADS‑B/flight-tracker data or to reconstruct activity during specific time windows. Respect the networks' rules and privacy expectations when harvesting or sharing data.

The [EuroScope for VATSIM](https://docs.vatsim.uk/General/Use%20of%20Software/EuroScope%20Setup%20Guide/) can be configured and installed to use VATSIM.

**VICE**

[Vice](https://pharr.org/vice/) is an air traffic control simulator, focused on TRACON and enroute scenarios; it provides an accurate simulation of the STARS system for TRACON and the ERAM system for enroute. Simulations have simulated traffic and virtual controllers covering other positions. Instructions may be given to aircraft verbally or via the keyboard; pilot responses are generated using speech synthesis. vice also supports multiple-user scenarios, where each person controls a different position at a facility. Pilot readbacks are generated via speech synthesis.

## Utilities

- `exiftool` — read metadata from images
- `gpsbabel` — convert between GPS formats
- `dump1090` (with RTL-SDR) — receive ADS-B,
  - visualize with `dump1090 --net`
- `OpenSky / ADS-B` data APIs — query historical flights (OpenSky API)
- `gpsd` + `gpspipe` — stream and log NMEA data, ie. `gpspipe -r`
- `RTKLIB` — when working with high-precision GNSS logs
- libraries in Python for parsing/visualizing
  - multiple options (_ie._ `pynmea2`, `pyproj`, `geopandas`, `folium`)
