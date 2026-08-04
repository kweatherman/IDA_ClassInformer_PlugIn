
// Main Dialog
#pragma once

#include "StdAfx.h"
#include <QtWidgets/QDialog>

#include "ui_dialog.h"

class MainDialog : public QDialog, public Ui::MainCIDialog
{
    Q_OBJECT
public:
    MainDialog(bool &optionPlaceStructs, bool &optionProcessStatic, bool &optionAudioOnDone, SegSelect::segments &segs, qstring &version, size_t animSwitch);

private:
	SegSelect::segments *segs;

private slots:
	void segmentSelect();
};

// Do main dialog, return true if canceled
bool doMainDialog(bool &optionPlaceStructs, bool &optionProcessStatic, bool &optionAudioOnDone, SegSelect::segments &segs, qstring &version, size_t animSwitch);
