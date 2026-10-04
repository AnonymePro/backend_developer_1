<!DOCTYPE html>
<html>
<head><title>SecureShop - Profile Picture Upload</title></head>
<body>
    <h1>SecureShop: Upload your profile picture (hardened)</h1>
    <form action="upload.php" method="post" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <input type="submit" value="Upload">
    </form>

    <h2>Uploaded files (served from a separate, non-executable path)</h2>
    <ul>
    <?php
        foreach (glob(__DIR__ . "/uploads/*") as $f) {
            $name = htmlspecialchars(basename($f));
            echo "<li><a href=\"uploads/$name\">$name</a></li>";
        }
    ?>
    </ul>
</body>
</html>
