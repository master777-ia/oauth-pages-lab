async function carregarSessao() {
  const status = document.getElementById("status");

  try {
    const response = await fetch("/api/me", {
      credentials: "include",
      cache: "no-store",
    });

    if (!response.ok) {
      status.textContent =
        "Nenhuma sessão neste navegador.";
      return;
    }

    const user = await response.json();

    status.textContent =
      `Sessão de ${user.email ?? user.displayName}.`;
  } catch {
    status.textContent =
      "Não foi possível consultar a sessão.";
  }
}

async function sair(event) {
  event.preventDefault();

  try {
    await fetch("/oauth/logout", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
    });

    window.location.replace("/?logout=1");
  } catch {
    alert("Não foi possível encerrar a sessão.");
  }
}

const logoutForm =
  document.querySelector(
    'form[action="/oauth/logout"]'
  );

if (logoutForm) {
  logoutForm.addEventListener(
    "submit",
    sair
  );
}

carregarSessao();
