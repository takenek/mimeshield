<?php

declare(strict_types=1);

namespace MimeShield\Tests\Integration;

use MimeShield\Ui\MessageUi;
use PHPUnit\Framework\TestCase;

/** I-17: the action gate must run before touching IMAP or re-verifying the message. */
final class MessageSaveCertLimitTest extends TestCase
{
    protected function setUp(): void
    {
        if (!MIMESHIELD_RC_LOADED) {
            self::markTestSkipped('needs Roundcube');
        }
        require_once dirname(__DIR__, 2) . '/mimeshield.php';
        $_POST = ['_uid' => '1', '_mbox' => 'INBOX'];
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $_POST = [];
        $_SESSION = [];
    }

    public function testExhaustedWindowStopsBeforeStorageAndFreshWindowReachesStorage(): void
    {
        $rc = (new \ReflectionClass(\rcmail::class))->newInstanceWithoutConstructor();
        $rc->storage = new class () {
            public int $calls = 0;

            public function set_folder(string $folder): void
            {
                $this->calls++;
                throw new \RuntimeException('stop before IMAP');
            }
        };
        $rc->output = new class () {
            /** @var list<string> */
            public array $messages = [];

            public function show_message(string $message, string $type): void
            {
                $this->messages[] = $message;
            }

            public function send(): never
            {
                throw new \RuntimeException('response sent');
            }
        };
        $plugin = (new \ReflectionClass(\mimeshield::class))->newInstanceWithoutConstructor();
        (new \ReflectionProperty(\mimeshield::class, 'rc'))->setValue($plugin, $rc);
        $ui = new MessageUi($plugin);

        $_SESSION['mimeshield_rl_savecert'] = array_fill(0, 20, time());
        $this->runAction($ui);
        self::assertSame(['mimeshield.ratelimited'], $rc->output->messages);
        self::assertSame(0, $rc->storage->calls);
        self::assertCount(20, $_SESSION['mimeshield_rl_savecert']);

        $_SESSION['mimeshield_rl_savecert'] = array_fill(0, 20, time() - 61);
        $this->runAction($ui);
        self::assertSame(1, $rc->storage->calls, 'the expired quota must not prevent normal requests');
        self::assertCount(1, $_SESSION['mimeshield_rl_savecert']);
    }

    private function runAction(MessageUi $ui): void
    {
        try {
            $ui->saveCertAction();
            self::fail('the action should send a response');
        } catch (\RuntimeException $e) {
            self::assertSame('response sent', $e->getMessage());
        }
    }
}
