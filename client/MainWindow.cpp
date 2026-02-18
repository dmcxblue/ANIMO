#include "MainWindow.h"
#include "ThemeManager.h"

#include <QVBoxLayout>
#include <QPushButton>
#include <QMenuBar>
#include <QMenu>
#include <QSlider>
#include <QLabel>
#include <QWidgetAction>
#include <QGraphicsDropShadowEffect>
#include <QMessageBox>
#include <QRegularExpression>


MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setWindowFlags(Qt::FramelessWindowHint | Qt::WindowSystemMenuHint);
    setAttribute(Qt::WA_TranslucentBackground);
    setWindowTitle("ANIMO");

    // Central widget with rounded corners
    QWidget *central = new QWidget(this);
    central->setObjectName("centralWidget");
    central->setStyleSheet(
        "#centralWidget { "
        " background-color: palette(Window); "
        " border-radius: 12px; "
        " }"
    );

    // Drop shadow
    QGraphicsDropShadowEffect *shadow = new QGraphicsDropShadowEffect();
    shadow->setBlurRadius(25.0);
    shadow->setColor(QColor(0, 0, 0, 160));
    shadow->setOffset(0, 5);
    central->setGraphicsEffect(shadow);

    QVBoxLayout *layout = new QVBoxLayout(central);
    layout->setContentsMargins(0,0,0,0);
    layout->setSpacing(0);

    // Custom title bar
	/*
    TitleBar *titleBar = new TitleBar(this);
    layout->addWidget(titleBar);
	*/
    // Menu bar
    QMenuBar *menuBar = new QMenuBar(this);
    QMenu *optionsMenu = menuBar->addMenu("Options");
    QMenu *helpMenu = menuBar->addMenu("Help");

    // Mode submenu
    QMenu *modeMenu = optionsMenu->addMenu("Mode");
    QAction *lightAction = new QAction("Light Mode", this);
    QAction *darkAction  = new QAction("Dark Mode", this);
    modeMenu->addAction(lightAction);
    modeMenu->addAction(darkAction);

    // Transparency submenu
    QMenu *transparencyMenu = optionsMenu->addMenu("Transparency");

    QWidget *sliderWidget = new QWidget();
    QHBoxLayout *sliderLayout = new QHBoxLayout(sliderWidget);
    sliderLayout->setContentsMargins(5, 2, 5, 2);
    sliderLayout->setSpacing(6);

    QLabel *label = new QLabel("100%");
    QSlider *slider = new QSlider(Qt::Horizontal);
    slider->setRange(30, 100);
    slider->setValue(100);
    slider->setFixedWidth(120);

    sliderLayout->addWidget(slider);
    sliderLayout->addWidget(label);

    QWidgetAction *sliderAction = new QWidgetAction(this);
    sliderAction->setDefaultWidget(sliderWidget);
    transparencyMenu->addAction(sliderAction);

    optionsMenu->addMenu(modeMenu);
    optionsMenu->addMenu(transparencyMenu);

    layout->addWidget(menuBar);

	
	// About action
	QAction *aboutAction = new QAction("About", this);
	helpMenu->addAction(aboutAction);
	
	// When clicked, show info box
	connect(aboutAction, &QAction::triggered, [this]() {
		QMessageBox::about(this,
			"About ANIMO",
			"ANIMO V1.0\n\nA macOS-style Qt application.\nBuilt with Qt Widgets and C++17.");
	});

    // Example content
    QPushButton *button = new QPushButton("Hello ANIMO!");
    layout->addWidget(button, 1, Qt::AlignCenter);

    central->setLayout(layout);
    setCentralWidget(central);

    // === Connections ===
    connect(lightAction, &QAction::triggered, [=]() { ThemeManager::applyLight(*qApp); });
    connect(darkAction,  &QAction::triggered, [=]() { ThemeManager::applyDark(*qApp); });

    connect(slider, &QSlider::valueChanged, [=](int value) {
        double opacity = value / 100.0;
        label->setText(QString("%1%").arg(value));
        central->setStyleSheet(QString(
            "#centralWidget { "
            " background-color: rgba(%1, %2, %3, %4); "
            " border-radius: 12px; "
            " }"
        ).arg(qApp->palette().color(QPalette::Window).red())
         .arg(qApp->palette().color(QPalette::Window).green())
         .arg(qApp->palette().color(QPalette::Window).blue())
         .arg(int(opacity * 255)));
    });
}
