<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Nothing to See Here</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        :root {
            --bg-color: #f8fafc;
            --card-bg: #ffffff;
            --text-color: #1f2937;
            --subtext-color: #6b7280;
            --shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
        }

        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', sans-serif;
            background-color: var(--bg-color);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }

        .card {
            background-color: var(--card-bg);
            padding: 2rem 3rem;
            border-radius: 12px;
            box-shadow: var(--shadow);
            text-align: center;
        }

        h1 {
            font-size: 2.5rem;
            color: var(--text-color);
            margin-bottom: 0.5rem;
        }

        p {
            font-size: 1.1rem;
            color: var(--subtext-color);
        }
    </style>
</head>
<body>
    <div class="card">
        <h1>Nothing to See Here</h1>
        <p>This page is intentionally left blank. But it’s got style.</p>
    </div>
</body>
</html>
