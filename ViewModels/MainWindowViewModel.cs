// ViewModels/MainWindowViewModel.cs
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input;
using Avalonia.Media;
using Avalonia.Styling;
using CrossPlatformCryptoTool.Models;
using CrossPlatformCryptoTool.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;

namespace CrossPlatformCryptoTool.ViewModels;

public partial class MainWindowViewModel : ViewModelBase
{
    private readonly IEncryptionService _encryptionService;

    private string _inputText = string.Empty;
    private string _outputText = string.Empty;
    private EncryptionAlgorithm _selectedAlgorithm = EncryptionAlgorithm.AES;
    private KeySize _selectedKeySize = KeySize.AES256;
    private CipherMode _selectedMode = CipherMode.CBC;
    private string _key = string.Empty;
    private string _iv = string.Empty;
    private bool _outputBase64 = true;
    private bool _isHashingAlgorithm;

    private string _statusMessage = "就绪";
    private bool _isStatusError = false;
    private IBrush _statusBrush = Brushes.Gray;
    private FontWeight _statusFontWeight = FontWeight.Normal;

    public MainWindowViewModel()
    {
        _encryptionService = new EncryptionService();

        EncryptCommand = new RelayCommand(ExecuteEncrypt);
        DecryptCommand = new RelayCommand(ExecuteDecrypt);
        ClearCommand = new RelayCommand(ExecuteClear);
        GenerateRandomKeyCommand = new RelayCommand(ExecuteGenerateRandomKey);
        GenerateRandomIVCommand = new RelayCommand(ExecuteGenerateRandomIV);
        SwapTextCommand = new RelayCommand(ExecuteSwapText);
        CopyOutputCommand = new AsyncRelayCommand(ExecuteCopyOutputAsync);
        SaveOutputCommand = new AsyncRelayCommand(ExecuteSaveOutputAsync);
        ToggleThemeCommand = new RelayCommand(ExecuteToggleTheme);

        // 初始化时设置 IsHashingAlgorithm
        UpdateHashingFlag();
    }

    // ... existing properties ...
    public string InputText
    {
        get => _inputText;
        set => SetProperty(ref _inputText, value);
    }

    public string OutputText
    {
        get => _outputText;
        set => SetProperty(ref _outputText, value);
    }

    public EncryptionAlgorithm SelectedAlgorithm
    {
        get => _selectedAlgorithm;
        set
        {
            if (SetProperty(ref _selectedAlgorithm, value))
            {
                UpdateHashingFlag();
                // 设置默认密钥长度
                if (_selectedAlgorithm == EncryptionAlgorithm.AES)
                    SelectedKeySize = KeySize.AES256;
                else if (_selectedAlgorithm == EncryptionAlgorithm.SM4)
                    SelectedKeySize = KeySize.SM4128;
            }
        }
    }

    public KeySize SelectedKeySize
    {
        get => _selectedKeySize;
        set => SetProperty(ref _selectedKeySize, value);
    }

    public CipherMode SelectedMode
    {
        get => _selectedMode;
        set => SetProperty(ref _selectedMode, value);
    }

    public string Key
    {
        get => _key;
        set => SetProperty(ref _key, value);
    }

    public string IV
    {
        get => _iv;
        set => SetProperty(ref _iv, value);
    }

    public bool OutputBase64
    {
        get => _outputBase64;
        set => SetProperty(ref _outputBase64, value);
    }

    public bool IsHashingAlgorithm
    {
        get => _isHashingAlgorithm;
        private set
        {
            if (SetProperty(ref _isHashingAlgorithm, value))
            {
                OnPropertyChanged(nameof(IsNotHashingAlgorithm));
            }
        }
    }

    public bool IsNotHashingAlgorithm => !IsHashingAlgorithm;

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public bool IsStatusError
    {
        get => _isStatusError;
        private set => SetProperty(ref _isStatusError, value);
    }

    public IBrush StatusBrush
    {
        get => _statusBrush;
        private set => SetProperty(ref _statusBrush, value);
    }

    public FontWeight StatusFontWeight
    {
        get => _statusFontWeight;
        private set => SetProperty(ref _statusFontWeight, value);
    }

    public ICommand EncryptCommand { get; }
    public ICommand DecryptCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand GenerateRandomKeyCommand { get; }
    public ICommand GenerateRandomIVCommand { get; }
    public ICommand SwapTextCommand { get; }
    public ICommand CopyOutputCommand { get; }
    public ICommand SaveOutputCommand { get; }
    public ICommand ToggleThemeCommand { get; }

    public IEnumerable<EncryptionAlgorithm> Algorithms => Enum.GetValues<EncryptionAlgorithm>();
    public IEnumerable<KeySize> KeySizes => Enum.GetValues<KeySize>();
    public IEnumerable<CipherMode> Modes => Enum.GetValues<CipherMode>();

    private void UpdateHashingFlag()
    {
        IsHashingAlgorithm = SelectedAlgorithm == EncryptionAlgorithm.SHA256 ||
                             SelectedAlgorithm == EncryptionAlgorithm.SHA512 ||
                             SelectedAlgorithm == EncryptionAlgorithm.SM3;
    }

    private void ExecuteEncrypt()
    {
        try
        {
            var request = new EncryptionRequest
            {
                InputText = InputText,
                Algorithm = SelectedAlgorithm,
                KeySize = SelectedKeySize,
                Mode = SelectedMode,
                Key = Key,
                IV = IV,
                OutputBase64 = OutputBase64
            };

            var result = _encryptionService.Encrypt(request);

            if (result.Success)
            {
                OutputText = result.Output;
                SetStatus("加密完成", false);
            }
            else
            {
                OutputText = string.Empty;
                SetStatus("错误: " + (string.IsNullOrEmpty(result.ErrorMessage) ? "未知错误" : result.ErrorMessage), true);
            }
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "加密异常");
        }
    }

    private void ExecuteDecrypt()
    {
        try
        {
            var request = new EncryptionRequest
            {
                InputText = InputText, // ciphertext
                Algorithm = SelectedAlgorithm,
                KeySize = SelectedKeySize,
                Mode = SelectedMode,
                Key = Key,
                IV = IV,
                OutputBase64 = OutputBase64
            };

            var result = _encryptionService.Decrypt(request);

            if (result.Success)
            {
                OutputText = result.Output; // plaintext
                SetStatus("解密完成", false);
            }
            else
            {
                OutputText = string.Empty;
                SetStatus("错误: " + (string.IsNullOrEmpty(result.ErrorMessage) ? "未知错误" : result.ErrorMessage), true);
            }
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "解密异常");
        }
    }

    private void ExecuteClear()
    {
        InputText = string.Empty;
        OutputText = string.Empty;
        Key = string.Empty;
        IV = string.Empty;
        SetStatus("已清除", false);
    }

    private void ExecuteGenerateRandomKey()
    {
        try
        {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var bytes = new byte[32]; //256位
            rng.GetBytes(bytes);
            Key = Convert.ToBase64String(bytes);
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "生成密钥失败");
        }
    }

    private void ExecuteGenerateRandomIV()
    {
        try
        {
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            var bytes = new byte[16]; //128位
            rng.GetBytes(bytes);
            IV = Convert.ToBase64String(bytes);
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "生成IV失败");
        }
    }

    private void ExecuteSwapText()
    {
        (InputText, OutputText) = (OutputText, InputText);
    }

    private async Task ExecuteCopyOutputAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(OutputText))
            {
                SetStatus("没有可复制的输出", true);
                return;
            }

            var lifetime = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
            var mainWindow = lifetime?.MainWindow;
            if (mainWindow == null)
            {
                SetStatus("无法访问主窗口以访问剪贴板", true);
                return;
            }

            var clipboard = mainWindow.Clipboard;
            if (clipboard == null)
            {
                SetStatus("无法访问剪贴板", true);
                return;
            }

            await clipboard.SetTextAsync(OutputText);
            SetStatus("已复制到剪贴板", false);
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "复制输出失败");
        }
    }

    private async Task ExecuteSaveOutputAsync()
    {
        try
        {
            if (string.IsNullOrEmpty(OutputText))
            {
                SetStatus("没有可保存的输出", true);
                return;
            }

            var lifetime = Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime;
            var mainWindow = lifetime?.MainWindow;
            if (mainWindow == null)
            {
                SetStatus("无法访问主窗口以显示保存对话框", true);
                return;
            }

            var dlg = new SaveFileDialog
            {
                Title = "保存输出到文件",
                DefaultExtension = "txt",
                Filters = new List<FileDialogFilter>
                {
                    new FileDialogFilter { Name = "Text File", Extensions = { "txt" } },
                    new FileDialogFilter { Name = "All Files", Extensions = { "*" } }
                }
            };

            var path = await dlg.ShowAsync(mainWindow);
            if (string.IsNullOrEmpty(path))
            {
                SetStatus("已取消保存", false);
                return;
            }

            await File.WriteAllTextAsync(path, OutputText);
            SetStatus($"已保存到 {path}", false);
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "保存文件失败");
        }
    }

    private void ExecuteToggleTheme()
    {
        try
        {
            var app = Application.Current;
            if (app == null)
            {
                SetStatus("无法切换主题：找不到应用实例", true);
                return;
            }

            // Toggle between Light and Dark
            var current = app.RequestedThemeVariant;
            var newVariant = current == ThemeVariant.Dark ? ThemeVariant.Light : ThemeVariant.Dark;
            app.RequestedThemeVariant = newVariant;
            SetStatus($"已切换为 {(newVariant == ThemeVariant.Dark ? "夜间" : "白天")}主题", false);
        }
        catch (Exception ex)
        {
            SetStatusFromException(ex, "切换主题失败");
        }
    }

    private void SetStatus(string message, bool isError)
    {
        StatusMessage = message;
        IsStatusError = isError;
        StatusBrush = isError ? Brushes.Red : Brushes.Gray;
        StatusFontWeight = isError ? FontWeight.Bold : FontWeight.Normal;
    }

    private void SetStatusFromException(Exception ex, string contextPrefix)
    {
        // Translate common exception types to Chinese explanations
        var typeName = ex.GetType().Name;
        string chineseExplanation = typeName switch
        {
            "CryptographicException" => "加密/解密失败，可能是密钥或IV不正确，或数据被破坏。",
            "FormatException" => "数据格式错误，可能是密文不是正确的编码格式。",
            "ArgumentNullException" => "缺少必需参数：请提供 Key 和 IV（如果算法需要）。",
            "ArgumentException" => "参数错误，请检查输入和所选算法/模式/密钥长度。",
            _ => string.Empty
        };

        // If exception message contains Chinese characters, keep original; otherwise include Chinese explanation
        var original = ex.Message ?? string.Empty;
        bool containsChinese = false;
        foreach (var ch in original)
        {
            if (ch >= 0x4e00 && ch <= 0x9fff) { containsChinese = true; break; }
        }

        if (containsChinese)
        {
            SetStatus($"{contextPrefix}: {original}", true);
        }
        else
        {
            var detail = !string.IsNullOrEmpty(chineseExplanation) ? chineseExplanation : "发生异常，请查看详细信息。";
            SetStatus($"{contextPrefix}: {detail} 原文: {original}", true);
        }
    }
}