import java.lang.classfile.Label;

import javax.swing.plaf.synth.Region;

import javafx.animation.*;
import javafx.application.Application;
import javafx.geometry.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.effect.*;
import javafx.scene.input.KeyCode;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import javafx.scene.shape.*;
import javafx.scene.text.*;
import javafx.stage.*;
import javafx.util.Duration;

/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║   Modern JavaFX Login Page — Dark Glassmorphism Theme    ║
 * ║   Run: javac --module-path <fx-path> --add-modules       ║
 * ║         javafx.controls LoginApp.java                    ║
 * ║   Then: java --module-path <fx-path> --add-modules       ║
 * ║         javafx.controls LoginApp                         ║
 * ╚══════════════════════════════════════════════════════════╝
 */
public class LoginApp extends Application {

    // ── Theme state ──────────────────────────────────────────────────────
    private boolean isDarkMode = true;
    private Scene   scene;
    private StackPane root;

    // ── UI references (needed for validation & theming) ──────────────────
    private TextField     usernameField;
    private PasswordField passwordField;
    private TextField     passwordVisible; // for show/hide toggle
    private CheckBox      rememberMe;
    private Label         feedbackLabel;
    private Button        loginButton;
    private VBox          card;
    private Pane          backgroundPane;
    private boolean       showingPassword = false;

    // ── Animated background orbs ─────────────────────────────────────────
    private Circle orb1, orb2, orb3;

    @Override
    public void start(Stage stage) {
        root = buildRoot();
        scene = new Scene(root, 1100, 720);

        // Load external CSS
        String css = getClass().getResource("login.css") != null
                ? getClass().getResource("login.css").toExternalForm()
                : "login.css";
        try { scene.getStylesheets().add(css); }
        catch (Exception ignored) { /* CSS file not found — styles still applied via code */ }

        // Apply initial theme class
        root.getStyleClass().add("dark-mode");

        stage.setTitle("SecureLogin — Sign In");
        stage.setScene(scene);
        stage.setMinWidth(400);
        stage.setMinHeight(500);
        stage.show();

        // Play entrance animation
        playCardEntrance();
        startOrbAnimation();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  ROOT LAYOUT — animated gradient background + card
    // ══════════════════════════════════════════════════════════════════════

    private StackPane buildRoot() {
        StackPane stack = new StackPane();

        // ── Background (gradient + floating orbs) ─────────────────────────
        backgroundPane = buildBackground();
        stack.getChildren().add(backgroundPane);

        // ── Centered login card ────────────────────────────────────────────
        card = buildCard();
        StackPane.setAlignment(card, Pos.CENTER);
        stack.getChildren().add(card);

        // ── Theme toggle (top right) ───────────────────────────────────────
        Button themeToggle = buildThemeToggle();
        StackPane.setAlignment(themeToggle, Pos.TOP_RIGHT);
        StackPane.setMargin(themeToggle, new Insets(20));
        stack.getChildren().add(themeToggle);

        return stack;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  BACKGROUND  — deep dark with glowing color orbs
    // ══════════════════════════════════════════════════════════════════════

    private Pane buildBackground() {
        Pane pane = new Pane();
        pane.getStyleClass().add("bg-pane");

        // Bind pane size to scene
        pane.prefWidthProperty().bind(
            javafx.beans.binding.Bindings.createDoubleBinding(
                () -> scene != null ? scene.getWidth()  : 1100,
                scene != null ? scene.widthProperty()  : new javafx.beans.property.SimpleDoubleProperty(1100)
            )
        );
        pane.prefHeightProperty().bind(
            javafx.beans.binding.Bindings.createDoubleBinding(
                () -> scene != null ? scene.getHeight() : 720,
                scene != null ? scene.heightProperty() : new javafx.beans.property.SimpleDoubleProperty(720)
            )
        );

        // Floating glow orbs
        orb1 = new Circle(260);
        orb1.getStyleClass().add("orb-1");
        orb1.setCenterX(150); orb1.setCenterY(160);

        orb2 = new Circle(200);
        orb2.getStyleClass().add("orb-2");
        orb2.setCenterX(900); orb2.setCenterY(550);

        orb3 = new Circle(140);
        orb3.getStyleClass().add("orb-3");
        orb3.setCenterX(800); orb3.setCenterY(120);

        pane.getChildren().addAll(orb1, orb2, orb3);
        return pane;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  LOGIN CARD — glassmorphism frosted panel
    // ══════════════════════════════════════════════════════════════════════

    private VBox buildCard() {
        VBox vbox = new VBox(0);
        vbox.getStyleClass().add("login-card");
        vbox.setMaxWidth(420);
        vbox.setMinWidth(380);
        vbox.setAlignment(Pos.TOP_CENTER);
        vbox.setPadding(new Insets(48, 48, 40, 48));

        // Initial invisible state for entrance animation
        vbox.setOpacity(0);
        vbox.setTranslateY(30);

        vbox.getChildren().addAll(
            buildLogoSection(),
            buildDivider(24),
            buildUsernameField(),
            buildDivider(14),
            buildPasswordField(),
            buildDivider(16),
            buildOptionsRow(),
            buildDivider(28),
            buildLoginButton(),
            buildDivider(14),
            feedbackLabel = buildFeedbackLabel(),
            buildDivider(28),
            buildDividerLine(),
            buildDivider(20),
            buildSignUpRow()
        );

        return vbox;
    }

    // ── Logo / Heading ───────────────────────────────────────────────────

    private VBox buildLogoSection() {
        VBox section = new VBox(6);
        section.setAlignment(Pos.CENTER);

        // Icon mark
        StackPane iconMark = new StackPane();
        iconMark.getStyleClass().add("logo-mark");
        iconMark.setPrefSize(52, 52);
        Label shield = new Label("⬡");
        shield.getStyleClass().add("logo-icon");
        Label inner  = new Label("✦");
        inner.getStyleClass().add("logo-icon-inner");
        iconMark.getChildren().addAll(shield, inner);
        VBox.setMargin(iconMark, new Insets(0, 0, 14, 0));

        Label title    = new Label("Welcome back");
        title.getStyleClass().add("card-title");

        Label subtitle = new Label("Sign in to your account to continue");
        subtitle.getStyleClass().add("card-subtitle");

        section.getChildren().addAll(iconMark, title, subtitle);
        return section;
    }

    // ── Username field ───────────────────────────────────────────────────

    private VBox buildUsernameField() {
        VBox group = new VBox(7);

        Label label = new Label("Email or Username");
        label.getStyleClass().add("field-label");

        // Icon + input wrapper
        HBox wrapper = new HBox(0);
        wrapper.getStyleClass().add("field-wrapper");
        wrapper.setAlignment(Pos.CENTER_LEFT);

        Label icon = new Label("✉");
        icon.getStyleClass().add("field-icon");

        usernameField = new TextField();
        usernameField.setPromptText("you@example.com");
        usernameField.getStyleClass().add("field-input");
        HBox.setHgrow(usernameField, Priority.ALWAYS);

        // Clear button
        Button clearBtn = new Button("✕");
        clearBtn.getStyleClass().add("field-clear-btn");
        clearBtn.setVisible(false);
        clearBtn.setOnAction(e -> usernameField.clear());
        usernameField.textProperty().addListener((obs, o, n) -> {
            clearBtn.setVisible(!n.isEmpty());
            clearFeedback();
        });

        wrapper.getChildren().addAll(icon, usernameField, clearBtn);

        // Focus glow effect
        addFocusGlow(usernameField, wrapper);

        group.getChildren().addAll(label, wrapper);
        return group;
    }

    // ── Password field ───────────────────────────────────────────────────

    private VBox buildPasswordField() {
        VBox group = new VBox(7);

        Label label = new Label("Password");
        label.getStyleClass().add("field-label");

        HBox wrapper = new HBox(0);
        wrapper.getStyleClass().add("field-wrapper");
        wrapper.setAlignment(Pos.CENTER_LEFT);

        Label icon = new Label("🔒");
        icon.getStyleClass().add("field-icon");

        passwordField   = new PasswordField();
        passwordVisible = new TextField();

        passwordField.setPromptText("Enter your password");
        passwordVisible.setPromptText("Enter your password");
        passwordField.getStyleClass().add("field-input");
        passwordVisible.getStyleClass().addAll("field-input", "password-visible");
        passwordVisible.setVisible(false);
        passwordVisible.setManaged(false);

        HBox.setHgrow(passwordField,   Priority.ALWAYS);
        HBox.setHgrow(passwordVisible, Priority.ALWAYS);

        // Sync text between the two
        passwordField.textProperty().addListener((obs, o, n) -> {
            if (!showingPassword) { passwordVisible.setText(n); clearFeedback(); }
        });
        passwordVisible.textProperty().addListener((obs, o, n) -> {
            if (showingPassword) { passwordField.setText(n); clearFeedback(); }
        });

        // Show/hide toggle button
        Button toggleBtn = new Button("👁");
        toggleBtn.getStyleClass().add("field-eye-btn");
        toggleBtn.setOnAction(e -> togglePasswordVisibility(toggleBtn));

        wrapper.getChildren().addAll(icon, passwordField, passwordVisible, toggleBtn);

        addFocusGlow(passwordField,   wrapper);
        addFocusGlow(passwordVisible, wrapper);

        group.getChildren().addAll(label, wrapper);
        return group;
    }

    // ── Options row (remember me + forgot password) ──────────────────────

    private HBox buildOptionsRow() {
        HBox row = new HBox();
        row.setAlignment(Pos.CENTER);

        rememberMe = new CheckBox("Remember me");
        rememberMe.getStyleClass().add("remember-check");

        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);

        Hyperlink forgot = new Hyperlink("Forgot password?");
        forgot.getStyleClass().add("forgot-link");
        forgot.setOnAction(e -> showForgotPasswordFeedback());

        row.getChildren().addAll(rememberMe, spacer, forgot);
        return row;
    }

    // ── Login button ──────────────────────────────────────────────────────

    private Button buildLoginButton() {
        loginButton = new Button("Sign In");
        loginButton.getStyleClass().add("login-btn");
        loginButton.setMaxWidth(Double.MAX_VALUE);
        loginButton.setPrefHeight(48);

        // Press scale animation
        loginButton.setOnMousePressed(e  -> scaleNode(loginButton, 0.97));
        loginButton.setOnMouseReleased(e -> scaleNode(loginButton, 1.00));

        loginButton.setOnAction(e -> handleLogin());

        // Allow Enter key from password field
        passwordField.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) handleLogin();
        });
        passwordVisible.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) handleLogin();
        });
        usernameField.setOnKeyPressed(e -> {
            if (e.getCode() == KeyCode.ENTER) passwordField.requestFocus();
        });

        return loginButton;
    }

    // ── Feedback label ────────────────────────────────────────────────────

    private Label buildFeedbackLabel() {
        Label lbl = new Label();
        lbl.getStyleClass().add("feedback-label");
        lbl.setMaxWidth(Double.MAX_VALUE);
        lbl.setAlignment(Pos.CENTER);
        lbl.setWrapText(true);
        lbl.setVisible(false);
        lbl.setManaged(false);
        return lbl;
    }

    // ── Divider line ──────────────────────────────────────────────────────

    private HBox buildDividerLine() {
        HBox row = new HBox(10);
        row.setAlignment(Pos.CENTER);

        Region left  = new Region(); left.getStyleClass().add("divider-line"); HBox.setHgrow(left,  Priority.ALWAYS);
        Label  text  = new Label("OR"); text.getStyleClass().add("divider-text");
        Region right = new Region(); right.getStyleClass().add("divider-line"); HBox.setHgrow(right, Priority.ALWAYS);

        row.getChildren().addAll(left, text, right);
        return row;
    }

    // ── Sign up row ───────────────────────────────────────────────────────

    private HBox buildSignUpRow() {
        HBox row = new HBox(4);
        row.setAlignment(Pos.CENTER);

        Label text = new Label("Don't have an account?");
        text.getStyleClass().add("signup-text");

        Hyperlink link = new Hyperlink("Create one");
        link.getStyleClass().add("signup-link");
        link.setOnAction(e -> showInfo("Account creation coming soon! 🚀"));

        row.getChildren().addAll(text, link);
        return row;
    }

    // ── Theme toggle button ───────────────────────────────────────────────

    private Button buildThemeToggle() {
        Button btn = new Button(isDarkMode ? "☀" : "◑");
        btn.getStyleClass().add("theme-toggle");
        btn.setOnAction(e -> {
            isDarkMode = !isDarkMode;
            btn.setText(isDarkMode ? "☀" : "◑");
            if (isDarkMode) {
                root.getStyleClass().remove("light-mode");
                root.getStyleClass().add("dark-mode");
            } else {
                root.getStyleClass().remove("dark-mode");
                root.getStyleClass().add("light-mode");
            }
            // Animate the toggle
            RotateTransition rt = new RotateTransition(Duration.millis(360), btn);
            rt.setByAngle(360);
            rt.play();
        });
        return btn;
    }

    // ── Helper: blank spacer ──────────────────────────────────────────────

    private Region buildDivider(double height) {
        Region r = new Region();
        r.setPrefHeight(height);
        r.setMinHeight(height);
        return r;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  LOGIN LOGIC — validation + feedback
    // ══════════════════════════════════════════════════════════════════════

    private void handleLogin() {
        String user = usernameField.getText().trim();
        String pass = passwordField.getText().trim();

        // ── Validation ────────────────────────────────────────────────────
        if (user.isEmpty() && pass.isEmpty()) {
            showError("Please enter your email and password.");
            shakeNode(card);
            return;
        }
        if (user.isEmpty()) {
            showError("Email or username is required.");
            shakeNode(usernameField.getParent());
            usernameField.requestFocus();
            return;
        }
        if (pass.isEmpty()) {
            showError("Password cannot be empty.");
            shakeNode(passwordField.getParent());
            passwordField.requestFocus();
            return;
        }
        if (user.contains("@") && !user.matches("^[\\w.+\\-]+@[\\w\\-]+\\.[a-zA-Z]{2,}$")) {
            showError("Please enter a valid email address.");
            shakeNode(usernameField.getParent());
            return;
        }
        if (pass.length() < 6) {
            showError("Password must be at least 6 characters.");
            shakeNode(passwordField.getParent());
            return;
        }

        // ── Simulated async login (pulse animation while "loading") ────────
        playLoadingState(true);

        PauseTransition pause = new PauseTransition(Duration.millis(1400));
        pause.setOnFinished(e -> {
            playLoadingState(false);
            // Demo: accept any valid-looking input
            if (user.equalsIgnoreCase("wrong") || pass.equals("wrong")) {
                showError("Invalid credentials. Please try again.");
                shakeNode(card);
            } else {
                showSuccess("Welcome back, " + (user.contains("@")
                        ? user.split("@")[0] : user) + "! 🎉");
                playSuccessAnimation();
            }
        });
        pause.play();
    }

    private void showForgotPasswordFeedback() {
        String user = usernameField.getText().trim();
        if (user.isEmpty()) {
            showInfo("Enter your email first, then click 'Forgot password?'");
            usernameField.requestFocus();
        } else {
            showInfo("Reset link sent to " + user + " (demo)");
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  FEEDBACK HELPERS
    // ══════════════════════════════════════════════════════════════════════

    private void showError(String msg) {
        feedbackLabel.setText("⚠  " + msg);
        feedbackLabel.getStyleClass().removeAll("feedback-success", "feedback-info");
        if (!feedbackLabel.getStyleClass().contains("feedback-error"))
            feedbackLabel.getStyleClass().add("feedback-error");
        revealFeedback();
    }

    private void showSuccess(String msg) {
        feedbackLabel.setText("✓  " + msg);
        feedbackLabel.getStyleClass().removeAll("feedback-error", "feedback-info");
        if (!feedbackLabel.getStyleClass().contains("feedback-success"))
            feedbackLabel.getStyleClass().add("feedback-success");
        revealFeedback();
    }

    private void showInfo(String msg) {
        feedbackLabel.setText("ℹ  " + msg);
        feedbackLabel.getStyleClass().removeAll("feedback-error", "feedback-success");
        if (!feedbackLabel.getStyleClass().contains("feedback-info"))
            feedbackLabel.getStyleClass().add("feedback-info");
        revealFeedback();
    }

    private void revealFeedback() {
        feedbackLabel.setVisible(true);
        feedbackLabel.setManaged(true);
        feedbackLabel.setOpacity(0);
        FadeTransition ft = new FadeTransition(Duration.millis(280), feedbackLabel);
        ft.setToValue(1.0);
        ft.play();
    }

    private void clearFeedback() {
        if (feedbackLabel.isVisible()) {
            FadeTransition ft = new FadeTransition(Duration.millis(200), feedbackLabel);
            ft.setToValue(0);
            ft.setOnFinished(e -> {
                feedbackLabel.setVisible(false);
                feedbackLabel.setManaged(false);
            });
            ft.play();
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  ANIMATIONS
    // ══════════════════════════════════════════════════════════════════════

    /** Fade + slide-up card entrance on startup */
    private void playCardEntrance() {
        PauseTransition delay = new PauseTransition(Duration.millis(120));
        delay.setOnFinished(e -> {
            FadeTransition fade = new FadeTransition(Duration.millis(600), card);
            fade.setFromValue(0); fade.setToValue(1);

            TranslateTransition slide = new TranslateTransition(Duration.millis(600), card);
            slide.setFromY(30); slide.setToY(0);
            slide.setInterpolator(Interpolator.EASE_OUT);

            ParallelTransition pt = new ParallelTransition(fade, slide);
            pt.play();
        });
        delay.play();
    }

    /** Horizontal shake on validation error */
    private void shakeNode(javafx.scene.Node node) {
        double ox = node.getTranslateX();
        TranslateTransition tt = new TranslateTransition(Duration.millis(60), node);
        tt.setAutoReverse(true);
        tt.setCycleCount(6);
        tt.setFromX(ox - 7); tt.setToX(ox + 7);
        tt.setOnFinished(e -> node.setTranslateX(ox));
        tt.play();
    }

    /** Scale press animation */
    private void scaleNode(javafx.scene.Node node, double scale) {
        ScaleTransition st = new ScaleTransition(Duration.millis(80), node);
        st.setToX(scale); st.setToY(scale);
        st.play();
    }

    /** Button loading pulse */
    private void playLoadingState(boolean loading) {
        if (loading) {
            loginButton.setText("Signing in…");
            loginButton.setDisable(true);
            loginButton.getStyleClass().add("login-btn-loading");

            // Pulsing opacity
            FadeTransition pulse = new FadeTransition(Duration.millis(600), loginButton);
            pulse.setFromValue(1.0); pulse.setToValue(0.65);
            pulse.setAutoReverse(true); pulse.setCycleCount(Animation.INDEFINITE);
           loginButton.setUserData(pulse);
            pulse.play();
        } else {
            loginButton.setText("Sign In");
            loginButton.setDisable(false);
            loginButton.getStyleClass().remove("login-btn-loading");
            if (loginButton.getUserData() instanceof FadeTransition ft) ft.stop();
            loginButton.setOpacity(1.0);
        }
    }

    /** Success: glow + brief scale-up */
    private void playSuccessAnimation() {
        ScaleTransition st = new ScaleTransition(Duration.millis(200), card);
        st.setToX(1.012); st.setToY(1.012);
        st.setAutoReverse(true); st.setCycleCount(2);
        card.getStyleClass().add("card-success");
        st.setOnFinished(e -> card.getStyleClass().remove("card-success"));
        st.play();
    }

    /** Slow floating drift of orbs in background */
    private void startOrbAnimation() {
        animateOrb(orb1,  8000,  40,  30);
        animateOrb(orb2,  11000, -35, -25);
        animateOrb(orb3,  7000,  25,  -35);
    }

    private void animateOrb(Circle orb, int durationMs, double dx, double dy) {
        if (orb == null) return;
        TranslateTransition tt = new TranslateTransition(Duration.millis(durationMs), orb);
        tt.setByX(dx); tt.setByY(dy);
        tt.setAutoReverse(true);
        tt.setCycleCount(Animation.INDEFINITE);
        tt.setInterpolator(Interpolator.EASE_BOTH);
        tt.play();
    }

    /** Adds focus glow — highlights the wrapper border when field is focused */
    private void addFocusGlow(Control field, HBox wrapper) {
        field.focusedProperty().addListener((obs, oldVal, focused) -> {
            if (focused) {
                wrapper.getStyleClass().add("field-wrapper-focused");
                FadeTransition ft = new FadeTransition(Duration.millis(180), wrapper);
                ft.setFromValue(0.85); ft.setToValue(1.0); ft.play();
            } else {
                wrapper.getStyleClass().remove("field-wrapper-focused");
            }
        });
    }

    /** Toggle password visibility between PasswordField and plain TextField */
    private void togglePasswordVisibility(Button btn) {
        showingPassword = !showingPassword;
        if (showingPassword) {
            passwordVisible.setText(passwordField.getText());
            passwordField.setVisible(false);    passwordField.setManaged(false);
            passwordVisible.setVisible(true);   passwordVisible.setManaged(true);
            passwordVisible.requestFocus();
            passwordVisible.positionCaret(passwordVisible.getText().length());
            btn.setText("🙈");
        } else {
            passwordField.setText(passwordVisible.getText());
            passwordVisible.setVisible(false);  passwordVisible.setManaged(false);
            passwordField.setVisible(true);     passwordField.setManaged(true);
            passwordField.requestFocus();
            passwordField.positionCaret(passwordField.getText().length());
            btn.setText("👁");
        }
    }

    public static void main(String[] args) { launch(args); }
}
