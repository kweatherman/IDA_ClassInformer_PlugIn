
// Main Dialog
#include "StdAfx.h"
#include "MainDialog.h"

#include <QtWidgets/QDialogButtonBox>


MainDialog::MainDialog(bool &optionPlaceStructs, bool &optionProcessStatic, bool &optionAudioOnDone, SegSelect::segments &segs, qstring &version, size_t /*animSwitch*/) : QDialog(QApplication::activeWindow())
{
    Ui::MainCIDialog::setupUi(this);
    setWindowFlags(windowFlags() & ~Qt::WindowContextHelpButtonHint);
    buttonBox->addButton("CONTINUE", QDialogButtonBox::AcceptRole);
    buttonBox->addButton("CANCEL", QDialogButtonBox::RejectRole);

    #define INITSTATE(obj,state) obj->setCheckState((state) ? Qt::Checked : Qt::Unchecked);
    INITSTATE(checkBox1, optionPlaceStructs);
    INITSTATE(checkBox2, optionProcessStatic);
    INITSTATE(checkBox3, optionAudioOnDone);
    #undef INITSTATE

    // Apply style sheet
    QFile file(QT_RES_PATH "style.qss");
    if (file.open(QFile::ReadOnly | QFile::Text))
        setStyleSheet(QTextStream(&file).readAll());

	this->segs = &segs;
    this->setWindowTitle(QString("Class Informer ") + QString(version.c_str()));

    // Setup banner widget - static banner
	QRect bannerGeometry(0, 0, 292, 74);
    QWidget *bannerWidget = NULL;

    {
		// Create the static banner (QLabel)
		QLabel *image = new QLabel(this);
		image->setObjectName(QString::fromUtf8("image"));
		image->setPixmap(QPixmap(QString::fromUtf8(":/res/banner.png")));
		image->setTextFormat(Qt::PlainText);
		image->setTextInteractionFlags(Qt::NoTextInteraction);
        #if QT_CONFIG(tooltip)
		image->setToolTip(QString::fromUtf8(""));
        #endif
		bannerWidget = image;
	}
	bannerWidget->setGeometry(bannerGeometry);
}

// On choose segments
void MainDialog::segmentSelect()
{
	SegSelect::select(*this->segs, (SegSelect::DATA_HINT | SegSelect::RDATA_HINT), "Choose segments to scan");
}

// Do main dialog, return true if canceled
bool doMainDialog(bool &optionPlaceStructs, bool &optionProcessStatic, bool &optionAudioOnDone, SegSelect::segments &segs, qstring &version, size_t animSwitch)
{
	bool result = true;
    MainDialog *dlg = new MainDialog(optionPlaceStructs, optionProcessStatic, optionAudioOnDone, segs, version, animSwitch);
    if (dlg->exec())
    {
        #define CHECKSTATE(obj,var) var = dlg->obj->isChecked()
        CHECKSTATE(checkBox1, optionPlaceStructs);
        CHECKSTATE(checkBox2, optionProcessStatic);
        CHECKSTATE(checkBox3, optionAudioOnDone);
        #undef CHECKSTATE
		result = false;
    }
	delete dlg;
    return(result);
}
