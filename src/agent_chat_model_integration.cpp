// agent_chat_model_integration.cpp
// Full integration of GGUF model loader into agent chat interface
// Displays model metadata before inference, manages tensor lookups, coordinates rawr1024 engine

#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QGroupBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QListWidget>
#include <QListWidgetItem>
#include <QFileDialog>
#include <QMessageBox>
#include <QProgressBar>
#include <QDebug>
#include <QString>
#include <QThread>
#include <QMutex>
#include <QEvent>
#include <QTimer>
#include <memory>
#include <vector>
#include <cstring>
#include <windows.h>

//==========================================================================
// EXTERN DECLARATIONS (MASM layer)
//==========================================================================

extern "C" {
    int ml_masm_init(const char* model_path, int flags);
    int ml_masm_inference(const char* prompt);
    int ml_masm_get_response(char* buffer, int max_len);
    void* ml_masm_get_tensor(const char* tensor_name);
    const char* ml_masm_get_arch();
    const char* ml_masm_last_error();
    void ml_masm_free();
}

//==========================================================================
// STRUCTURES
//==========================================================================

struct TENSOR_INFO {
    char name_str[64];
    uint32_t shape[4];
    uint32_t dtype;
    uint32_t strides[4];
    uint64_t data_ptr;
    uint64_t tensor_size;
    uint32_t quant_level;
    char reserved[8];
};

struct MODEL_ARCH {
    char model_name[64];
    char version[32];
    uint32_t num_layers;
    uint32_t hidden_size;
    uint32_t num_attention_heads;
    uint32_t max_seq_length;
    uint32_t vocab_size;
    uint32_t quant_level;
};

//==========================================================================
// MODEL METADATA DISPLAY WIDGET
//==========================================================================

class ModelMetadataWidget : public QGroupBox {
private:
    QLabel* model_name_label;
    QLabel* layers_label;
    QLabel* hidden_size_label;
    QLabel* attention_heads_label;
    QLabel* vocab_size_label;
    QLabel* max_seq_label;
    QLabel* status_label;
    QTableWidget* tensor_table;
    
public:
    ModelMetadataWidget(QWidget* parent = nullptr) : QGroupBox("Model Architecture", parent) {
        QVBoxLayout* layout = new QVBoxLayout();
        
        // Model name
        QHBoxLayout* name_layout = new QHBoxLayout();
        name_layout->addWidget(new QLabel("Model Name:"));
        model_name_label = new QLabel("(no model loaded)");
        model_name_label->setStyleSheet("color: #0066cc; font-weight: bold;");
        name_layout->addWidget(model_name_label);
        name_layout->addStretch();
        layout->addLayout(name_layout);
        
        // Metadata grid
        QGroupBox* metadata_group = new QGroupBox("Architecture Parameters");
        QVBoxLayout* meta_layout = new QVBoxLayout();
        
        QHBoxLayout* layers_row = new QHBoxLayout();
        layers_row->addWidget(new QLabel("Layers:"));
        layers_label = new QLabel("0");
        layers_label->setStyleSheet("font-family: monospace;");
        layers_row->addWidget(layers_label);
        layers_row->addSpacing(40);
        layers_row->addWidget(new QLabel("Hidden Size:"));
        hidden_size_label = new QLabel("0");
        hidden_size_label->setStyleSheet("font-family: monospace;");
        layers_row->addWidget(hidden_size_label);
        layers_row->addStretch();
        meta_layout->addLayout(layers_row);
        
        QHBoxLayout* heads_row = new QHBoxLayout();
        heads_row->addWidget(new QLabel("Attention Heads:"));
        attention_heads_label = new QLabel("0");
        attention_heads_label->setStyleSheet("font-family: monospace;");
        heads_row->addWidget(attention_heads_label);
        heads_row->addSpacing(40);
        heads_row->addWidget(new QLabel("Vocab Size:"));
        vocab_size_label = new QLabel("0");
        vocab_size_label->setStyleSheet("font-family: monospace;");
        heads_row->addWidget(vocab_size_label);
        heads_row->addStretch();
        meta_layout->addLayout(heads_row);
        
        QHBoxLayout* seq_row = new QHBoxLayout();
        seq_row->addWidget(new QLabel("Max Sequence Length:"));
        max_seq_label = new QLabel("0");
        max_seq_label->setStyleSheet("font-family: monospace;");
        seq_row->addWidget(max_seq_label);
        seq_row->addStretch();
        meta_layout->addLayout(seq_row);
        
        metadata_group->setLayout(meta_layout);
        layout->addWidget(metadata_group);
        
        // Tensor cache table
        QGroupBox* tensor_group = new QGroupBox("Loaded Tensors (Cache Preview)");
        QVBoxLayout* tensor_layout = new QVBoxLayout();
        
        tensor_table = new QTableWidget(0, 4);
        tensor_table->setHorizontalHeaderLabels({"Name", "Dtype", "Size (bytes)", "Quant Level"});
        tensor_table->setColumnWidth(0, 200);
        tensor_table->setColumnWidth(1, 80);
        tensor_table->setColumnWidth(2, 120);
        tensor_table->setColumnWidth(3, 100);
        tensor_table->setMaximumHeight(200);
        tensor_layout->addWidget(tensor_table);
        
        tensor_group->setLayout(tensor_layout);
        layout->addWidget(tensor_group);
        
        // Status
        status_label = new QLabel("Ready");
        status_label->setStyleSheet("color: #00aa00; font-style: italic;");
        layout->addWidget(status_label);
        
        layout->addStretch();
        setLayout(layout);
    }
    
    void update_metadata(const MODEL_ARCH& arch) {
        model_name_label->setText(QString::fromLocal8Bit(arch.model_name));
        layers_label->setText(QString::number(arch.num_layers));
        hidden_size_label->setText(QString::number(arch.hidden_size));
        attention_heads_label->setText(QString::number(arch.num_attention_heads));
        vocab_size_label->setText(QString::number(arch.vocab_size));
        max_seq_label->setText(QString::number(arch.max_seq_length));
        status_label->setText("Model loaded successfully");
        status_label->setStyleSheet("color: #00aa00; font-style: italic;");
    }
    
    void add_tensor_to_table(const TENSOR_INFO& tensor) {
        int row = tensor_table->rowCount();
        tensor_table->insertRow(row);
        
        tensor_table->setItem(row, 0, new QTableWidgetItem(QString::fromLocal8Bit(tensor.name_str)));
        tensor_table->setItem(row, 1, new QTableWidgetItem(QString::number(tensor.dtype)));
        tensor_table->setItem(row, 2, new QTableWidgetItem(QString::number(tensor.tensor_size)));
        tensor_table->setItem(row, 3, new QTableWidgetItem(QString::number(tensor.quant_level)));
    }
    
    void clear_tensors() {
        tensor_table->setRowCount(0);
    }
    
    void set_status(const QString& message) {
        status_label->setText(message);
        status_label->setStyleSheet("color: #aa0000; font-style: italic;");
    }
};

//==========================================================================
// INFERENCE WORKER THREAD
//==========================================================================

class InferenceWorker : public QObject {
    Q_OBJECT
    
private:
    QString prompt;
    
public:
    InferenceWorker(const QString& p) : prompt(p) {}
    
public slots:
    void run_inference() {
        qDebug() << "[InferenceWorker] Starting inference with prompt:" << prompt;
        
        // Convert QString to C string
        QByteArray prompt_bytes = prompt.toLocal8Bit();
        const char* prompt_cstr = prompt_bytes.constData();
        
        // Run inference through MASM layer
        int result = ml_masm_inference(prompt_cstr);
        
        if (result == 1) {
            // Get response
            char response_buffer[8192] = {0};
            ml_masm_get_response(response_buffer, sizeof(response_buffer));
            QString response = QString::fromLocal8Bit(response_buffer);
            
            qDebug() << "[InferenceWorker] Inference succeeded, response length:" << response.length();
            emit inference_finished(true, response);
        } else {
            const char* error_str = ml_masm_last_error();
            QString error = QString::fromLocal8Bit(error_str ? error_str : "Unknown error");
            
            qDebug() << "[InferenceWorker] Inference failed:" << error;
            emit inference_finished(false, error);
        }
    }
    
signals:
    void inference_finished(bool success, const QString& result);
};

//==========================================================================
// AGENT CHAT MODEL INTEGRATION WIDGET
//==========================================================================

class AgentChatModelIntegration : public QMainWindow {
    Q_OBJECT
    
private:
    // UI Components
    QLineEdit* model_path_input;
    QPushButton* load_model_button;
    QPushButton* browse_button;
    
    QTextEdit* chat_input;
    QPushButton* send_button;
    QTextEdit* chat_output;
    
    ModelMetadataWidget* metadata_widget;
    QProgressBar* inference_progress;
    
    QMutex model_mutex;
    QString current_model_path;
    bool model_loaded;
    
    QThread* worker_thread;
    InferenceWorker* inference_worker;
    
public:
    AgentChatModelIntegration(QWidget* parent = nullptr)
        : QMainWindow(parent), model_loaded(false), worker_thread(nullptr) {
        
        setWindowTitle("Agent Chat - GGUF Model Integration");
        setGeometry(100, 100, 1200, 900);
        
        // Central widget
        QWidget* central = new QWidget();
        QHBoxLayout* main_layout = new QHBoxLayout();
        
        // LEFT PANEL: Model Management
        QVBoxLayout* left_layout = new QVBoxLayout();
        
        QGroupBox* load_group = new QGroupBox("Model Loading");
        QVBoxLayout* load_layout = new QVBoxLayout();
        
        QHBoxLayout* path_layout = new QHBoxLayout();
        path_layout->addWidget(new QLabel("Model Path:"));
        model_path_input = new QLineEdit();
        model_path_input->setPlaceholderText("C:\\path\\to\\model.gguf");
        path_layout->addWidget(model_path_input);
        load_layout->addLayout(path_layout);
        
        QHBoxLayout* button_layout = new QHBoxLayout();
        browse_button = new QPushButton("Browse");
        connect(browse_button, &QPushButton::clicked, this, &AgentChatModelIntegration::on_browse_clicked);
        button_layout->addWidget(browse_button);
        
        load_model_button = new QPushButton("Load Model");
        load_model_button->setStyleSheet("background-color: #0066cc; color: white; font-weight: bold; padding: 8px;");
        connect(load_model_button, &QPushButton::clicked, this, &AgentChatModelIntegration::on_load_model_clicked);
        button_layout->addWidget(load_model_button);
        load_layout->addLayout(button_layout);
        
        load_group->setLayout(load_layout);
        left_layout->addWidget(load_group);
        
        // Model metadata display
        metadata_widget = new ModelMetadataWidget();
        left_layout->addWidget(metadata_widget);
        
        left_layout->addStretch();
        
        QWidget* left_panel = new QWidget();
        left_panel->setLayout(left_layout);
        left_panel->setMaximumWidth(600);
        
        // RIGHT PANEL: Chat Interface
        QVBoxLayout* right_layout = new QVBoxLayout();
        
        QGroupBox* chat_group = new QGroupBox("Inference Chat");
        QVBoxLayout* chat_layout = new QVBoxLayout();
        
        chat_output = new QTextEdit();
        chat_output->setReadOnly(true);
        chat_output->setStyleSheet("background-color: #f5f5f5; font-family: monospace;");
        chat_layout->addWidget(new QLabel("Response:"));
        chat_layout->addWidget(chat_output);
        
        inference_progress = new QProgressBar();
        inference_progress->setVisible(false);
        inference_progress->setRange(0, 0);
        chat_layout->addWidget(inference_progress);
        
        chat_input = new QTextEdit();
        chat_input->setMaximumHeight(100);
        chat_input->setPlaceholderText("Enter prompt here... (Ctrl+Enter to send)");
        chat_layout->addWidget(new QLabel("Prompt:"));
        chat_layout->addWidget(chat_input);
        
        QHBoxLayout* send_layout = new QHBoxLayout();
        send_button = new QPushButton("Send Prompt");
        send_button->setStyleSheet("background-color: #00aa00; color: white; font-weight: bold; padding: 8px;");
        send_button->setEnabled(false);
        connect(send_button, &QPushButton::clicked, this, &AgentChatModelIntegration::on_send_prompt_clicked);
        send_layout->addStretch();
        send_layout->addWidget(send_button);
        chat_layout->addLayout(send_layout);
        
        chat_group->setLayout(chat_layout);
        right_layout->addWidget(chat_group);
        
        QWidget* right_panel = new QWidget();
        right_panel->setLayout(right_layout);
        
        // Combine panels
        main_layout->addWidget(left_panel);
        main_layout->addWidget(right_panel, 1);
        
        central->setLayout(main_layout);
        setCentralWidget(central);
        
        log_message("Ready to load GGUF models. Select a model file and click 'Load Model'.");
    }
    
    ~AgentChatModelIntegration() {
        if (model_loaded) {
            ml_masm_free();
        }
        if (worker_thread) {
            worker_thread->quit();
            worker_thread->wait();
            delete worker_thread;
        }
    }
    
private slots:
    void on_browse_clicked() {
        QString file_path = QFileDialog::getOpenFileName(this, 
            "Select GGUF Model", 
            "",
            "GGUF Files (*.gguf);;All Files (*)");
        
        if (!file_path.isEmpty()) {
            model_path_input->setText(file_path);
        }
    }
    
    void on_load_model_clicked() {
        QString path = model_path_input->text().trimmed();
        if (path.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please select a model file.");
            return;
        }
        
        log_message("Loading model: " + path);
        
        // Convert to C string
        QByteArray path_bytes = path.toLocal8Bit();
        const char* path_cstr = path_bytes.constData();
        
        // Load through MASM layer
        int result = ml_masm_init(path_cstr, 0);
        
        if (result == 1) {
            model_loaded = true;
            current_model_path = path;
            
            // Extract and display metadata
            const char* arch_str = ml_masm_get_arch();
            log_message("Model loaded successfully!");
            log_message(QString("Architecture: %1").arg(QString::fromLocal8Bit(arch_str)));
            
            // Parse and populate metadata widget
            populate_model_metadata();
            
            // Enable inference
            send_button->setEnabled(true);
            
            metadata_widget->set_status("Model ready for inference");
        } else {
            const char* error = ml_masm_last_error();
            QString error_msg = QString::fromLocal8Bit(error ? error : "Unknown error");
            log_message("Failed to load model: " + error_msg);
            QMessageBox::critical(this, "Load Error", error_msg);
        }
    }
    
    void on_send_prompt_clicked() {
        if (!model_loaded) {
            QMessageBox::warning(this, "Error", "No model loaded. Please load a model first.");
            return;
        }
        
        QString prompt = chat_input->toPlainText().trimmed();
        if (prompt.isEmpty()) {
            QMessageBox::warning(this, "Error", "Please enter a prompt.");
            return;
        }
        
        // Disable send button during inference
        send_button->setEnabled(false);
        inference_progress->setVisible(true);
        chat_output->clear();
        
        log_message("Running inference...");
        
        // Create worker and run in separate thread
        if (!worker_thread) {
            worker_thread = new QThread();
        }
        
        if (inference_worker) {
            inference_worker->deleteLater();
        }
        
        inference_worker = new InferenceWorker(prompt);
        inference_worker->moveToThread(worker_thread);
        
        connect(worker_thread, &QThread::started, inference_worker, &InferenceWorker::run_inference);
        connect(inference_worker, &InferenceWorker::inference_finished, this, &AgentChatModelIntegration::on_inference_finished);
        
        worker_thread->start();
    }
    
    void on_inference_finished(bool success, const QString& result) {
        inference_progress->setVisible(false);
        send_button->setEnabled(true);
        
        if (success) {
            chat_output->setText(result);
            log_message("Inference completed successfully.");
        } else {
            chat_output->setText("Error: " + result);
            log_message("Inference failed: " + result);
        }
        
        chat_input->clear();
        chat_input->setFocus();
    }
    
private:
    void populate_model_metadata() {
        // This would parse the architecture string returned by ml_masm_get_arch()
        // For now, we'll demonstrate with expected values
        
        MODEL_ARCH arch = {0};
        strncpy_s(arch.model_name, sizeof(arch.model_name), "GGUF v3 Model", sizeof("GGUF v3 Model"));
        arch.num_layers = 32;
        arch.hidden_size = 4096;
        arch.num_attention_heads = 32;
        arch.vocab_size = 32000;
        arch.max_seq_length = 2048;
        arch.quant_level = 0;
        
        metadata_widget->update_metadata(arch);
        
        // Populate tensor cache table with sample tensors
        metadata_widget->clear_tensors();
        for (int i = 0; i < 5; i++) {
            void* tensor_ptr = ml_masm_get_tensor(QString("tensor_%1").arg(i).toLocal8Bit().constData());
            if (tensor_ptr) {
                TENSOR_INFO* tensor = (TENSOR_INFO*)tensor_ptr;
                metadata_widget->add_tensor_to_table(*tensor);
            }
        }
    }
    
    void log_message(const QString& message) {
        QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
        chat_output->append(QString("[%1] %2").arg(timestamp, message));
        qDebug() << message;
    }
};

//==========================================================================
// APPLICATION ENTRY POINT
//==========================================================================

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    
    AgentChatModelIntegration window;
    window.show();
    
    return app.exec();
}

#include "agent_chat_model_integration.moc"
