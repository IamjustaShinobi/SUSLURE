import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.*;
import javafx.scene.text.Font;
import javafx.stage.Stage;

public class ModernLoginUI extends Application {

    @Override
    public void start(Stage stage) {

        // Main container
        StackPane root = new StackPane();

        // Gradient background
        BackgroundFill bgFill = new BackgroundFill(
                new LinearGradient(0, 0, 1, 1, true, CycleMethod.NO_CYCLE,
                        new Stop(0, Color.web("#4facfe")),
                        new Stop(1, Color.web("#00f2fe"))
                ),
                CornerRadii.EMPTY,
                Insets.EMPTY
        );
        root.setBackground(new Background(bgFill));

        // Login Card
        VBox card = new VBox(15);
        card.setAlignment(Pos.CENTER);
        card.setPadding(new Insets(30));
        card.setMaxWidth(300);
        card.setStyle(
                "-fx-background-color: white;" +
                "-fx-background-radius: 15;" +
                "-fx-effect: dropshadow(gaussian, rgba(0,0,0,0.2), 20,0,0,5);"
        );

        // Title
        Label title = new Label("Login");
        title.setFont(new Font("Arial", 24));

        // Username Field
        TextField username = new TextField();
        username.setPromptText("Username");
        username.setStyle(inputStyle());

        // Password Field
        PasswordField password = new PasswordField();
        password.setPromptText("Password");
        password.setStyle(inputStyle());

        // Login Button
        Button loginBtn = new Button("LOGIN");
        loginBtn.setPrefWidth(200);
        loginBtn.setStyle(buttonStyle());

        // Hover effect
        loginBtn.setOnMouseEntered(e -> 
            loginBtn.setStyle(buttonHoverStyle())
        );
        loginBtn.setOnMouseExited(e -> 
            loginBtn.setStyle(buttonStyle())
        );

        // Action
        loginBtn.setOnAction(e -> {
            System.out.println("Username: " + username.getText());
            System.out.println("Password: " + password.getText());
        });

        // Add all to card
        card.getChildren().addAll(title, username, password, loginBtn);

        root.getChildren().add(card);

        Scene scene = new Scene(root, 600, 400);
        stage.setTitle("Modern Login UI");
        stage.setScene(scene);
        stage.show();
    }

    // Input field style
    private String inputStyle() {
        return "-fx-pref-height: 40;" +
               "-fx-background-radius: 10;" +
               "-fx-border-radius: 10;" +
               "-fx-border-color: #ccc;" +
               "-fx-padding: 0 10;";
    }

    // Button style
    private String buttonStyle() {
        return "-fx-background-color: linear-gradient(#4facfe, #00f2fe);" +
               "-fx-text-fill: white;" +
               "-fx-font-weight: bold;" +
               "-fx-background-radius: 20;";
    }

    // Button hover style
    private String buttonHoverStyle() {
        return "-fx-background-color: linear-gradient(#43e97b, #38f9d7);" +
               "-fx-text-fill: white;" +
               "-fx-font-weight: bold;" +
               "-fx-background-radius: 20;";
    }

    public static void main(String[] args) {
        launch(args);
    }
}