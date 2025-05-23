
// Main Dialog
#pragma once

#include "stdafx.h"
#include <QtWidgets/QDialog>
#include <SegSelect.h>

#include "ui_dialog.h"

class MainDialog : public QDialog, public Ui::MainCIDialog
{
    Q_OBJECT
public:
    MainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone, SegSelect::segments &segs, qstring &version, size_t animSwitch);

private:	
	SegSelect::segments *segs;

private slots:
	void segmentSelect();
};

// Do main dialog, return TRUE if canceled
BOOL doMainDialog(BOOL &optionPlaceStructs, BOOL &optionProcessStatic, BOOL &optionAudioOnDone, __out SegSelect::segments &segs, qstring &version, size_t animSwitch);
