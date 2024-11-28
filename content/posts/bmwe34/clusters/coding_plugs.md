---
title: Coding Plugs
---

A coding plug is a mechanically keyed or electronically coded device/plug, that can open or bridge circuits in a particular component, therefore allowing it to operate differently dependent on the type of plug installed.

BMW used a mechanical coding plug which simply opened or bridged circuits to assign market specific data [to the instrument cluster](/instrument-clusters) of the E23, E24, E28 and E30 vehicles. With the introduction of the E32 in 1988 and the E34 in 1989, electronic coding plugs were utilized in the instrument cluster.

The change to an electronic coding plug which allowed market specific data to be assigned to the instrument cluster also contained Non-Volatile Random Access Memory (NV-RAM), which provided an ability to retain vehicle specific data in the plug such as:

- Vehicle Identification Number (VIN)
- Accumulated Total Mileage
- Service Indicator (SI) Information
- Coding Plug Number
- Fuel Tank Size data
- Other Necessary Data

By using a plug that is able to store data, the instrument cluster can be replaced without loosing vehicle mileage, unless the coding plug is damaged.

With the introduction of vehicles like the E31 and E38 the instrument cluster no longer utilizes a coding plug since it receives most of its input signals directly from a control module, EKM (E31) or IKE (E38), this allows vehicle data to be directly stored in the con- trol module and the instrument cluster is no longer coded. For these vehicles and newer models, market specific data is stored in the control module (EKM or IKE). By coding these modules by way of ZCS coding (refer to ZCS coding) market specific data is assigned/released to the control module.

{{< notice >}}
Coding Plug: Intergrated Circuit (IC) Details
{{< /notice >}}
{{< callout emoji="❇️" text="The chip used in BMW E34 dashboards is a physical dongle which plugs in the back of the dash cluster. This coding plug contains amongs other, the dashboard callibration. The older code plugs are brown and contain a national semiconductor NMC9346EN. The GQ-4X is reading it as a generic 93C46B (B = '16 bit mode') semiconductor. The brown codeplugs were replaced with the blue code plugs, containing a variation of the 93C46B. More details in the References page below." >}}

---

The user @kfister posted in 2007 on [bimmerboard.com](http://www.bimmerboard.com/forums/posts/420803) forum with all the messages he manage to dump from the BMW E34 Coding Plug ROM // EEPROM. He also noted that the Code Plug has copies of frame number, ZCS key for storage, mileage, and bitmapped options (*shown below*).

{{< details "Coding Plug EEPROM Dump" >}}
CODE_NR_2
e34/e32
CODE_NR_3
e34/e32
SIA_TEMP_FAKTOR
wert_01
GETRIEBE_SIA_WEG
100.000_km
GETRIEBE_SIA_TAGE
1825_tage
DATA_VALID
datensatz_gueltig
TANKGEBER
tauchrohrgeber
IB_EIN_ENTRIEGELN
nicht_aktiv
GETRIEBE
handschaltung
PARK/NEUTRAL_EINGANG
nicht_aktiv
MRA_TAKTUNG
nicht_aktiv
SCHLUPFSCHWELLENOFFSET
nicht_aktiv
SCHLUPFBANDMODIFIKATION
nicht_aktiv
AMR_TYP
typ_3
BMR_TYP
typ_2
K_ZAHL_WEG
4574_imp/km
STEIGUNG_EINSPRITZ_KENNL
m60b40
ZYLINDER_ZAHL
8_zylinder
MOTOR_ART
benziner
MOTOR_FAKTOR
4_imp/umdrehung
SPRACHE
englisch_us
ZEIT_EINHEIT
12_stunden
TEMPERATUR_EINHEIT
grad_f
WEGSTRECKE_EINHEIT
mls
ABSCHALTDREHZAHL_ANLASSER
8_zylinder_benziner
ZEITDAUER_BIS_ABSCHALTUNG
benziner
SCHALT_KRITERIUM_EWS_3
8_zylinder_benziner
EWS_3_SCHNITTSTELLE
nicht_aktiv
CODE_NR_1
e34/e32
CODE_NR_4
e34/e32
CODE_NR_5
e34/e32
GURTWARNUNG_GONG
nicht_aktiv
LAENDERVARIANTE
us
TANK_KENNLINIE
81_l_stahl
TANK_GAS_KENNLINIE
kennlinie_01
TANK_GAS_KENNLINIE_WINKEL
kennlinie_01
SIA_GRENZE_INSPEKTION
32.200_km
SIA_GRENZDREHZAHL
4500_u/min
SIA_GRENZE_ZEIT
0_tage
OELSERVICE_ANZAHL
2_service
WARNUNG_GESCHW_LIMIT
nicht_aktiv
ANZEIGE_KVA/OEL
kva
TEMPERATUR_KENNLINIE
kennlinie_03
SCHWELLE_UEBERDREHZAHL
7200_u/min
DZM_SKALA_ENDWERT
7000_upm_4_imp/kwu
AUSTAUSCHPUNKT
nicht_aktiv
OFFSET_GESAMTWEGSTRECKE
0_km
TACHO_SKALA_ENDWERT
160_mph_ece/us
TEMPERATUR_ANZEIGEWINKEL
kennlinie_02
TACHO_SKALA_ENDWERT_KOMPL
160_mph_ece/us
K_ZAHL
4534_imp/km
K_ZAHL_RED
4534_imp/km
LICHTWARNUNG
aktiv
REST_LITER_FAKTOR
16_l
SIA_ANZEIGE
aktiv
SIA_ANZEIGEDAUER
10_sec
SIA_DZ_FAKTOR
wert_01
SIA_ROT/GELB_SEGMENTE
aus_mit_gruen
TACHO_SKALA_ENDWERT_RED
240_km/h
TANK_KENNLINIE_WINKEL
81_l_stahl
TEMPERATUR_KENNL_VERSCHL
kennlinie_02
WARNUNG_GESCHW_LIMIT_2
nicht_aktiv
WARNUNG_GESCHW_LIMIT_RED
nicht_aktiv
CHECK_CONTROL_VERSION
us
EINSPRITZART
vollbank_1ti_signal
GETRIEBE_ART
keine_anzeige
K_ZAHL_BC
4534_imp/km
K_ZAHL_KOMPL
4534_imp/km
KOMBI_ART
high_kombi
LAENDER_EINHEITEN
us
TANK_KENNLINIE_BC
81_l_stahl
VENTILVERZUG_FAKTOR_A
0
VENTILVERZUG_FAKTOR_B
0
VERBRAUCH_EINHEIT
mpg_us
WARNUNG_GESCHW_LIM_KOMPL
nicht_aktiv
WARNUNG_UEBERTEMPERATUR
130_grad_celsius
EDC_KENNFELD
dv200
M21_DIESEL
nicht_aktiv
M40_ODER_M50
nicht_aktiv
M51_DIESEL
nicht_aktiv
TEMPERATURFUEHLER
innenfuehler
ZYLINDER_4_BENZIN
nicht_aktiv
ZYLINDER_6_BENZIN
nicht_aktiv
{{</ details >}}

**Coding Plug Identification**

Each coding plug features a stored 5-digit numerical code that varies between model/equipment, etc. The code can be read out through the instrument cluster display by pressing the odometer reset button and turning the ignition switch to KL R. The coding plug number will be display in the instrument cluster matrix.

{{< imgcap title="BMW Coding Plug Identification" src="/posts/images/bmw_coding_plug.png" >}}

**Coding Plug Overview**

Since the introduction of the E32 several versions of instrument cluster coding plugs have been introduced, this section will provide an overview of the different versions, plus provide identification and coding information.

The E32/E34 Instrument cluster coding plugs progressed through three variations of design.

* **MY. 11/88-02/89**

The original E32/E34 instrument cluster coding plug was installed in the wiring harness connector (X16) which plugged into the instrument cluster. This plug contained all of the vehicle specific coding data for the instrument cluster and retained accumulated mileage and service interval information.

* **MY. 02/89-09/91**

The E32/E34 instrument cluster and coding plug were redesigned in Feb. '89. As a result of this redesign the coding plug became an external component and plugged directly into the back of the instrument cluster, no longer part of the X16 connector.

* **MY 09/90 [revision]**

In 9/90 the cluster was slightly redesigned again to address changes in the fuel gauge and some minor physical changes. The electronics of the cluster as well as the coding plug were upgraded considerably.

The coding plug and the instrument cluster are not compatible with the earlier redesign. The printed circuit board and the coding plug are colored blue for distinction over the components of the earlier redesigned cluster.

The new blue coding plug is also keyed differently to prevent unintentional exchange with the earlier coding plug.

* **MY 09/91 and above**

After 9/91 production, the instrument cluster coding plug can be coded using the ZCS function within CIP by selecting the specific module via the DISplus/GT1/SSS . The physical characteristics of the coding plug did not change.

A replacement uncoded coding plug must be coded after installa- tion into the instrument cluster, refer to ZCS coding section in this manual.

---

{{< details "**Expand for Photos (Images)**" >}}
![](https://www.petberger.de/pet-racing/E34/UNTERLAGEN/KI/KI/KI.htm21.jpg)
![](https://www.petberger.de/pet-racing/E34/UNTERLAGEN/KI/KI/KI.htm23.jpg)
{{< /details >}}

**References**

* [BMW Technical Documentation - Coding Plug](https://ia801005.us.archive.org/11/items/BMWTechnicalTrainingDocuments/ST406%20Coding%20%26%20Programming/03%20Coding%20Plug.pdf) *(PDF) (Archive)*
* [Modifying a BMW E34 M5 Dash Chip](https://pcmhacking.net/forums/viewtopic.php?f=17&t=5379#p79787) *(NMC9346EN)*
* [More details on E34 Coding Plugs](https://www.bmwe34.net/E34main/Maintenance/Electrical/Capacitors.htm)
* [Uploading Encoder Firmware from BROWN<>BLUE Coding Plugs](https://www.drive2.ru/l/604922436495883811/)
* [Flashing the Instrument Cluster encoder - Mileage Correction](https://www.drive2.ru/l/614432387442415076/)