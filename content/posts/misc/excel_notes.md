---
title: "Excel Notes"
url: "/misc/excel"
---

Quick and easy way to do various things in Microsoft Excel, and when possible, corresponding functionalities in Apple's MacOS Numbers app equivalent.

**Reference a cell from another sheet**

To reference a cell from another sheet in Microsoft Excel, you simply use do the following:

1. Lets say you have two sheets in your Excel file, an "A" sheet, and a "B" sheet
2. You want to reference a particular cell from "A" sheet on the "B" sheet
3. To do so, in "B" sheet, you simply use notation `SheetName![Cell]`
4. For example, using `=SheetA!H2` somewhere in "B" sheet would show values from cell `H2` of sheet "A"
5. It's possible to use all of Excel's functionalities this way, for example: `=SUM(SheetA!H2 * 100)` and so on

**Reorder `Column` to another place in Excel Table**

To move or reorder a particular column in a sheet to a different place, simply:

1. Select the whole column by pressing it's header (ie. column letters `A`, `B` ...)
2. Move your mouse pointer to an edge of the selected column until you get a "hand" cursor symbol
3. Hold `Shift` key on your Keyboard, and click the edge of the column you want to move
4. Move the mouse to the position you want to move the column to
5. Release the click once you found the perfect place where the column is supposed to be at

Note: Similarly, you may want to replace a particular column with the one you've selected. To do so, follow the steps as described above, but instead of the `Shift` key, use the `Option/Alt` key instead, and move the column with the mouse to a particular other column you want to replace it with.

**Other Resources**

* [How to organize dates by week in Excel](https://www.storylane.io/tutorials/how-to-organize-dates-by-week-in-excel)
* [How to organize and createa a Report in Excel](https://www.storylane.io/tutorials/how-to-create-a-report-microsoft-excel)
* [How to make a Bar Graph in Excel](https://www.storylane.io/tutorials/how-to-make-a-bar-graph-in-microsoft-excel)