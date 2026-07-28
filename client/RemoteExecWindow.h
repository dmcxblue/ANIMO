#ifndef REMOTEEXECWINDOW_H
#define REMOTEEXECWINDOW_H

#include <QComboBox>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStackedWidget>
#include <QTableWidget>
#include <QWidget>

class RemoteExecTransport;

// RemoteExecWindow - shell-style interactive UI over pluggable
// RemoteExecTransport implementations (Azure VM runCommand, HTTP
// webshell, HTTP SSTI).
//
// Layout:
//   left rail  : saved targets from RemoteExecTargetStore + New/Edit/Delete
//   center     : shell output (read-only) + command line
//   right rail : transport summary + one-click actions (IMDS grab etc.)
class RemoteExecWindow : public QWidget {
    Q_OBJECT
public:
    explicit RemoteExecWindow(QWidget *parent = nullptr);
    ~RemoteExecWindow() override;

private slots:
    void refreshTargetList();
    void onTargetSelected();
    void onNewTarget();
    void onEditTarget();
    void onDeleteTarget();
    void onDuplicateTarget();
    void onKindComboChanged(int index);
    void onExecuteCommand();
    void onCancelCommand();
    void onSaveTargetFromEditor();
    void onOneClickIMDS();
    void onOneClickWhoami();
    void onOneClickTestSsti();

private:
    void setupUi();
    void applyStyle();
    void loadEditorFrom(const QString &targetId);   // empty = new
    void appendOutput(const QString &line, const QString &color = QString());
    void ensureTransportForCurrentTarget();

    // Target list rail
    QListWidget    *targetList;
    QPushButton    *newBtn;
    QPushButton    *editBtn;
    QPushButton    *dupBtn;
    QPushButton    *deleteBtn;

    // Center: output + command line
    QPlainTextEdit *outputArea;
    QLineEdit      *commandEdit;
    QPushButton    *runBtn;
    QPushButton    *cancelBtn;

    // Right rail: transport info + one-click actions
    QComboBox      *oneClickResourceCombo;
    QPushButton    *oneClickImdsBtn;
    QPushButton    *oneClickWhoamiBtn;
    QPushButton    *oneClickTestSstiBtn;

    // Editor panel (inline, not a dialog)
    QLineEdit      *ed_name;
    QComboBox      *ed_kind;
    QStackedWidget *ed_stack;

    // Editor pane: Azure VM
    QLineEdit      *az_token;
    QLineEdit      *az_vmId;
    QComboBox      *az_osType;

    // Editor pane: HTTP webshell + shared with SSTI
    QLineEdit      *hw_baseUrl;
    QComboBox      *hw_method;
    QLineEdit      *hw_cmdParam;
    QLineEdit      *hw_extraQuery;    // "k1=v1&k2=v2" convenience string
    QLineEdit      *hw_headers;       // "Header-Name: value; Another: v"
    QComboBox      *hw_extractor;
    QLineEdit      *hw_regex;
    QLineEdit      *hw_markerStart;
    QLineEdit      *hw_markerEnd;
    QSpinBox       *hw_timeoutMs;

    // Editor pane: SSTI (extends the HTTP fields above)
    QComboBox      *ssti_engine;
    QLineEdit      *ssti_payload;
    QComboBox      *ssti_cmdEscape;

    QPushButton    *ed_saveBtn;
    QPushButton    *ed_cancelBtn;

    // Editor state
    QString         editingId;   // empty => new; else UUID of the target being edited

    // Transport lifetime
    RemoteExecTransport *transport = nullptr;
    QString              activeTargetId;
};

#endif  // REMOTEEXECWINDOW_H
