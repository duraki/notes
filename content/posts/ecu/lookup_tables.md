---
title: "Lookup Tables"
---

The ECU Lookup Tables is a special file format "BDM". It is used to read the contents of the ECU and dumping the parameter values that describe specific tune.

Modifying the contents is done by searching the hex for known patterns in a hexadecimal editors based on these *Lookup Tables*. There is a large number of lookup tables describing parameter details such as: *throttle position vs rpm*, *coolant temp vs rpm*, and so on.

When you modify the contents of this binary [ECU File Data](/ecu-file-formats) in a hexadecimal editor, you are changing a specific tune and therefore increase or decrease the performance and overall state of the vehicle itself.

Typically for Stage1 map (ie. the *tweaks* of your tune), would change between 80 to 120 parameters.

### Example: *Lookup Table* **~** `AUDI ECU ME7.1`

The file hosted on [Github *(PDF)* 🇩🇪](https://github.com/zarboz/BMW-XDFs/blob/master/Datasheets/Audi_R4-5V_T_132kW_ME7.pdf) might provide more details and final table reference. The screenshot below is a an example of the lookup function found in one of the PDF pages, lets say:

```
ID|Section|Version|Description
51|   MS  |  3.0  |Motorsteugern Uberischt
XX|   ..  |  ...  |...
```

{{< imgcap title="AUDI R4/%v ME7.1 Example Lookup Function (Fig.1)" src="/posts/images/audi/audi_r4-5v-t-132kw-me7-function.png" >}}

### Example: *Lookup Table* **~** `BMW DME MS45` *[for WinOLS]*

The file hosted on [Github *(XML)* 🇩🇪](https://raw.githubusercontent.com/zarboz/BMW-XDFs/refs/heads/master/MS45-XDF/MS45.xdf) contains a relevant `*.xdf` file for BMW MS45 ECU/DME including relevant byte position and map information.

```xml
<!-- Written Tue May 28 09:08:17 MDT 2019 -->
<XDFFORMAT version="1.50">
  <!--  XDF HEADER DESC. -->
  <XDFHEADER>
    <fileversion>Version 1</fileversion>
    <deftitle>WinOLS (10053.ols (Original) - )</deftitle>
    <description>Original</description>
    <author>mesim translator</author>
    <baseoffset>0</baseoffset>
    <DEFAULTS datasizeinbits="8" sigdigits="2" outputtype="1" signed="0" lsbfirst="1" float="0" />
    <REGION type="0xFFFFFFFF" startaddress="0x0" size="0x100000" regionflags="0x0" name="Binary File" desc="This region describes the bin file edited by this XDF" />
    <CATEGORY index="0x0" name="My maps" />
    <CATEGORY index="0x1" name="AUX_Adaptation_of_reference_and_: &quot;_Adaptation of reference and non-reference edges&quot;" />
    <CATEGORY index="0x2" name="AUX_Blocking_of_the_air_conditio: &quot;_Blocking of the air conditioner compressor&quot;" />
    <CATEGORY index="0x3" name="AUX_Calculating_the_pulse_width_: &quot;_Calculating the pulse width modulation&quot;" />
    <CATEGORY index="0x4" name="AUX_Calculation_of_delay: &quot;_Calculation of delay&quot;" />
    <!--  ....... -->
  </XDFHEADER>

  <!--  XDF CONST. CONT -->
  <XDFCONSTANT uniqueid="0x0">
    <title>C_ABC_INC_CONV_MON</title>
    <description>Anti bounce counter increment (additive value in case of ADC error)</description>
    <CATEGORYMEM index="0" category="52" />
    <EMBEDDEDDATA mmedaddress="0x40240" mmedelementsizebits="8" />
    <units>-</units>
    <decimalpl>3</decimalpl>
    <datatype>0</datatype>
    <unittype>0</unittype>
    <DALINK index="0" />
    <MATH equation="X">
      <VAR id="X" />
    </MATH>
  </XDFCONSTANT>

  <!--  ....... -->
  <!--  ....... -->
```

### Example: *BMW E34 Lookup Tables* **~** `BMW E34 DME/ECU` Related XDFs

* [BMW E34 M50B25 525i Series 5 - `*.xdf* *(w. DME model 402, NON-TU, MY. 93)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_ecu403_soft950_M50_B25.xdf)
* [BMW E34/E36 M50B25 525i - `*.xdf* *(w. DME model 402, chip 599, NON-TU, MY. 93)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_ecu403_soft950_M50_B25.xdf)
* [BMW E34/E36 M50B25 525i - `*.xdf* *(w. DME model 402, chip 599, NON-TU, MY. 93)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_ecu403_soft950.xdf)
* [BMW E34/E36 M50B25TU 525i - `*.xdf* - *(w. DME model 405, chip 951, TU/VANOS, MY. 92-94)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_dme405_soft951.xdf)
* [BMW E34/E36 M50B28TU 528i - `*.xdf* - *(w. DME model/chip 641, OBD2 flash)*, also known as `**MS40.1**`](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/MS41_version641.xdf), also look at [BOSCH M5.2.1 DME (`BMW E36 318i`)](https://github.com/zarboz/M5.2.1)
* [BMW E34 MS43.X DME ECU](https://github.com/ms4x-net/ms43) XDFs and firmware dumps, 
* [RomRaider](https://github.com/RomRaider/RomRaider) [ECU *def. files* for Siemens MS40.1 DME ECU](https://github.com/ba114/Siemens-MS41)
* [BMW SIEMENS MS41 DME ECU](https://github.com/ba114/Siemens-MS41) RomRaider ECU *def files*

### Example: *Other BMW Lookup Tables* **~** `BMW DME/ECU` Related XDFs

* [BMW E46/E83/E60 DME/ECU `SIEMENS MS45-MS45.X`](https://github.com/pazi88/Siemens_ms45_RR-definitions) definition files for [RomRaider](), *incl.* [stock ROM dumps](https://github.com/pazi88/Siemens_ms45_RR-definitions/tree/master/Stock%20ROMs), [TunerPro XDFs](https://github.com/pazi88/Siemens_ms45_RR-definitions/tree/master/RR-definitions) (1) and [corrected XDFs](https://github.com/pazi88/Siemens_ms45_RR-definitions/tree/master/Other%20files/XDF%20definitions) (2), [a2l](https://github.com/pazi88/Siemens_ms45_RR-definitions/tree/master/Other%20files/A2L), [adx](https://github.com/pazi88/Siemens_ms45_RR-definitions/blob/master/Other%20files/ADX/BMW%20MS45%20-%20125000%20baud.adx), [reveng prototypes](https://github.com/pazi88/Siemens_ms45_RR-definitions/tree/master/Other%20files/MS45%20Prototypes), and [tuned mapfiles](https://github.com/rkneeshaw/MS45.1-ESS-TS2) for BMW E46 330i ZHP *(MS45.1 DME)* [BOSCH DME/ECU Pnouts Repository](https://github.com/typhoniks/Bosch-ECU-Pinout) for various vehicles *incl.* the [BMW's one](https://github.com/typhoniks/Bosch-ECU-Pinout/tree/main/Bosch%20M%205.2%20(BMW)), [...](https://github.com/typhoniks/Bosch-ECU-Pinout/tree/main/Bosch%20M%205.2.1%20(BMW))
* [AC Control Module (Arduino) for BMW E36 w/ MS43 ECU swap](https://github.com/ffrizzo/e36-can/tree/main)
* [BMW E28 745i Series 7 - `*.xdf` *(single chip)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/745i_singleCHIP_64K.xdf)
* [BMW Exx 750iL Series 7 - `*.xdf` *(w. DME model 156)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/750iL_156.xdf)
* [BMW E30 M20 Series 3 *(MY. 87)* `*.xdf` *(w. DME model 153)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW87_E30_153dme.xdf), specifically based on *BMW E30 '87 325i M20B25TU`*
* [BMW E30 M20 Series 3 *(MY. 87)* `*.xdf` *(w. DME model 153)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW87_E30_153dme.xdf), specifically based on *BMW E30 '87 325i M20B25TU`*, also XDF for [very rare engine//dme combo](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_027_DME_E30_4K.xdf), model E30 4K 2732 *(MY. 84-86)*
* [BMW E30 M42X Series 3 *(MY. 90-91)* `*.xdf` *(w. DME model 175)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_175_318i_soft378.xdf)
* [BMW E30 M20 Series 3 *(MY. 88-92)* `*.xdf` *(w. DME model 179)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_DME_179.xdf)
* [BMW E30 M20 Series 3 **EURO** model *(ECU `0 280 200 081`) - Bosch Motronic 1.1* `*.xdf` *(w. DME model 081)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_DME_179.xdf)
* [BMW E30 M20B25 325i Series 3 *(MY. 81-91)* `*.xdf` *(w. DME model 173)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/BMW_M20B25_ecu173_sw705.xdf)
* [BMW MSS54/MSS54HP](https://github.com/saildot4k/MSS54-XDFs) XDFs, can be modified as described in [README](https://github.com/saildot4k/MSS54-XDFs?tab=readme-ov-file#mss54-xdfs)
* [TunerPro.net listing](https://www.tunerpro.net/downloadBinDefs.htm#BMW) for related BMW XDFs, also [here](https://www.tunerpro.net/download/bins/BMW/)



### Example: *Other Cars*

* [Golf MK3 VR6 ECU 219, sw 109 *(MY. 94-95)* - `*.xdf` - *(w. Motronic ME2.9)*](https://github.com/zarboz/BMW-XDFs/blob/master/Misc%20BMW%20Xdfs/Golf_VR6_0261203219_soft109.xdf), also [TunerPro.net listing](https://www.tunerpro.net/downloadBinDefs.htm#VW)
* [Audi ME7.2 TunerPro Virginizer](https://github.com/zarboz/Me72-Virginizer) XDFs that can factory reset DME under test

### Other Resources

* [Bosch Motronic Checksum Correction Tool](https://github.com/matiss/motronic-checksum) helps you fix CRC errors supporting all OS platforms (MacOS//WinNT//Linux)
* [Siemens MS4X Wiki](https://www.ms4x.net/index.php?title=Main_Page) for MS4X DME/ECU specific topics, *incl.* [flashing tools](https://www.ms4x.net/index.php?title=Flashing_Tools), [retrofitting MAP sensor on DME itself](https://www.ms4x.net/index.php?title=Siemens_MS43_Retrofit_MAP_Sensor), [rear O2 i/o AC sensors](https://www.ms4x.net/index.php?title=Use_Rear_O2_Inputs_For_Analog_Sensors)
* [Speeduino Standalone ECU Docs Manual](https://wiki.speeduino.com/en/home), also see [megasquirt](https://megasquirt.info/), [haltech](https://www.haltech.com/), [aem](https://www.aemelectronics.com/?q=products/programmable-engine-management-systems), [motec](https://www.motec.com.au/)
* [OLDSKULLTUNING.com](https://oldskulltuning.com/)
* **Books:** [Performance Fuel Injection Systems HP1557: How to Design, Build, Modify, and Tune EFI and ECU Systems](https://www.amazon.com/dp/1557885575) - `~32.XX USD`; [High-Performance Fuel Injection Sys-OP](https://www.amazon.com/High-Perf-Fuel-Injection-Systems-Banish/dp/1932494901/ref=pd_sim_14_2?_encoding=UTF8&psc=1&refRID=E8GE9XS0TJKATGJC3GBD) - `~42.XX USD`; [Engine Management: Advanced Tuning](https://www.amazon.com/Engine-Management-Advanced-Greg-Banish/dp/1932494421/ref=pd_sim_14_1?_encoding=UTF8&psc=1&refRID=E8GE9XS0TJKATGJC3GBD) - `~30.XX USD`